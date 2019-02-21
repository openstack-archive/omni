"""
Copyright 2016 Platform9 Systems Inc.(http://www.platform9.com)
Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""

import json
import time

from credsmgrclient.client import Client
from credsmgrclient.common import exceptions
from keystoneauth1.access.service_catalog import ServiceCatalogV3
from keystoneauth1.exceptions import EndpointNotFound
from keystoneauth1 import loading
from neutron.db import omni_resources
from neutron_lib.exceptions import NeutronException
from novaclient import client as novaclient
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import loopingcall
from oslo_utils import reflection

import boto3
import botocore
import requests

aws_group = cfg.OptGroup(name='AWS',
                         title='Options to connect to an AWS environment')
aws_opts = [
    cfg.StrOpt('secret_key', help='Secret key of AWS account', secret=True),
    cfg.StrOpt('access_key', help='Access key of AWS account', secret=True),
    cfg.StrOpt('region_name', help='AWS region'),
    cfg.StrOpt('az', help='AWS availability zone'),
    cfg.IntOpt('wait_time_min', help='Maximum wait time for AWS operations',
               default=5),
    cfg.IntOpt('wait_interval', help='Wait interval for AWS operations',
               default=5),
    cfg.BoolOpt('use_credsmgr', help='Should credsmgr endpoint be used',
                default=True)
]

ks_group = cfg.OptGroup(name='keystone_authtoken',
                        title="Options to authenticate services")
ks_opts = [cfg.IntOpt('timeout', help='timeout value for http requests',
                      default=600)]
neutron_opts = [
    cfg.StrOpt('nova_region_name', help='Region used for neutron service'),
]

cfg.CONF.register_opts(neutron_opts)
cfg.CONF.register_group(aws_group)
cfg.CONF.register_opts(aws_opts, group=aws_group)
cfg.CONF.register_opts(ks_opts, group=ks_group)
aws_conf = cfg.CONF.AWS

LOG = logging.getLogger(__name__)


class _FixedIntervalWithTimeoutLoopingCall(loopingcall.LoopingCallBase):
    """A fixed interval looping call with timeout checking mechanism."""

    _RUN_ONLY_ONE_MESSAGE = _("A fixed interval looping call with timeout"
                              " checking and can only run one function at"
                              " at a time")

    _KIND = _('Fixed interval looping call with timeout checking.')

    def start(self, interval, initial_delay=None, stop_on_exception=True,
              timeout=0):
        start_time = time.time()

        def _idle_for(result, elapsed):
            delay = round(elapsed - interval, 2)
            if delay > 0:
                func_name = reflection.get_callable_name(self.f)
                LOG.warning('Function %(func_name)r run outlasted '
                            'interval by %(delay).2f sec',
                            {'func_name': func_name,
                             'delay': delay})
            elapsed_time = time.time() - start_time
            if timeout > 0 and elapsed_time > timeout:
                raise loopingcall.LoopingCallTimeOut(
                    _('Looping call timed out after %.02f seconds') %
                    elapsed_time)
            return -delay if delay < 0 else 0

        return self._start(_idle_for, initial_delay=initial_delay,
                           stop_on_exception=stop_on_exception)


# Currently, default oslo.service version(newton) is 1.16.0.
# Once we upgrade oslo.service >= 1.19.0, we can remove temporary
# definition _FixedIntervalWithTimeoutLoopingCall
if not hasattr(loopingcall, 'FixedIntervalWithTimeoutLoopingCall'):
    loopingcall.FixedIntervalWithTimeoutLoopingCall = \
        _FixedIntervalWithTimeoutLoopingCall


class AwsException(NeutronException):
    message = "AWS Error: '%(error_code)s' - '%(message)s'"


def _process_exception(e, dry_run):
    if dry_run:
        error_code = e.response['Code']
        if not error_code == 'DryRunOperation':
            raise AwsException(error_code='AuthFailure',
                               message='Check your AWS authorization')
    else:
        if isinstance(e, botocore.exceptions.ClientError):
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            raise AwsException(error_code=error_code, message=error_message)
        elif isinstance(e, AwsException):
            # If the exception is already an AwsException, do not nest it.
            # Instead just propagate it up.
            raise e
        else:
            # TODO(exceptions): This might display all Exceptions to the user
            # which might be irrelevant, keeping it until it becomes stable
            error_message = e.message
            raise AwsException(error_code="NeutronError",
                               message=error_message)


def aws_exception(fn):
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            _process_exception(e, kwargs.get('dry_run'))
    return wrapper


def get_credentials_from_conf():
    secret_key = aws_conf.secret_key
    access_key = aws_conf.access_key
    if not access_key or not secret_key:
        raise AwsException(error_code=400, message="AWS credentials not found")
    return dict(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key
    )


def _is_present(old_rules, rule):
    LOG.debug('Existing rules - %s', str(old_rules))
    LOG.debug('New rule - %s', str(rule))
    for old_rule in old_rules:
        # FromPort in AWS starts from 0 but in OpenStack it starts from 1.
        # Instead of revoking existing rules to create new ones because of this
        # difference ignore difference in FromPort if it is 0 or 1.
        if (old_rule.get('FromPort', -1) == rule.get('FromPort', -1) or
                old_rule.get('FromPort') in [0, 1] and
                rule.get('FromPort') in [0, 1]) and \
                (old_rule.get('ToPort', -1) == rule.get('ToPort', -1)) and \
                (old_rule.get('IpProtocol', -1) == rule.get('IpProtocol', -1))\
                and (sorted(old_rule.get('IpRanges', [])) ==
                     sorted(rule.get('IpRanges', []))):
            return True
    return False


def _is_same(old_rules, new_rules):
    if new_rules:
        new_rules = _remove_duplicate_sg_rules(new_rules)
    is_same = True
    for new_rule in new_rules:
        if not _is_present(old_rules, new_rule):
            is_same = False
    return is_same


def _remove_duplicate_sg_rules(rules):
    LOG.debug('Checking for duplicate rules in %s', str(rules))
    distinct = [rules[0]]
    for rule in rules[1:]:
        is_distinct = True
        for x in distinct:
            if x.get('FromPort', -1) == rule.get('FromPort', -1) and \
                    x.get('ToPort', -1) == rule.get('ToPort', -1) and \
                    sorted(x.get('IpRanges', [])) == \
                    sorted(rule.get('IpRanges', [])):
                is_distinct = False
        if is_distinct:
            distinct.append(rule)
    LOG.debug('Deduplicated rules - %s', str(distinct))
    return distinct


def _run_ec2_sg_fn(fn, *args, **kwargs):
    """
    Runs the function passed in `fn` argument and ignores
    InvalidPermission.Duplicate and InvalidPermission.NotFound errors.
    Function to be used only for security group revoke_* and authorize_*
    functions only.
    """
    try:
        fn(*args, **kwargs)
    except botocore.exceptions.ClientError as ce:
        LOG.debug('Local arguments - %s', str(locals()))
        exception_msg = str(ce)
        if 'InvalidPermission.Duplicate' in exception_msg:
            LOG.info('Security group rule present in AWS')
        elif 'InvalidPermission.NotFound' in exception_msg:
            LOG.info('Security group rule absent in AWS')
        else:
            raise


def get_credentials_using_credsmgr(context, project_id=None):
    try:
        keystone_url = cfg.CONF.keystone_authtoken.auth_uri
        headers = {'Content-Type': 'application/json',
                   'X-Auth-Token': context.auth_token}
        response = requests.get(keystone_url + "/v3/auth/catalog",
                                headers=headers)
        sc = ServiceCatalogV3(response.json()['catalog'])
        region_name = cfg.CONF.nova_region_name
        credsmgr_endpoint = sc.url_for(
            service_type='credsmgr', region_name=region_name)
        token = context.auth_token
        credsmgr_client = Client(credsmgr_endpoint, token=token)
        if not project_id:
            project_id = context.tenant
        _, body = credsmgr_client.credentials.credentials_get(
            'aws', project_id)
        return body
    except (EndpointNotFound, exceptions.HTTPBadGateway):
        LOG.warning("Unable to get credentials using credsmgrclient. "
                    "Getting credentials from config file.")
        return get_credentials_from_conf()
    except exceptions.HTTPNotFound:
        raise


def get_session_from_conf(section_name):
    """Get session using section name."""
    auth = loading.load_auth_from_conf_options(cfg.CONF, section_name)
    session = loading.load_session_from_conf_options(cfg.CONF, section_name,
                                                     auth=auth)
    return session


class AwsUtils(object):

    def __init__(self):
        self._nova_client = None
        self._keystone_session = None
        self._wait_time_sec = 60 * aws_conf.wait_time_min
        self.nova_api_version = "2"
        self.interval = aws_conf.wait_interval

    def get_nova_client(self):
        if self._nova_client is None:
            session = get_session_from_conf('nova')
            self._nova_client = novaclient.Client(
                self.nova_api_version, session=session,
                region_name=cfg.CONF.nova.region_name)
        return self._nova_client

    def get_keystone_session(self):
        """Get keystone session required while calling for subnets."""
        if self._keystone_session is None:
            self._keystone_session = get_session_from_conf(
                'keystone_authtoken')
        return self._keystone_session

    def _get_ec2_client(self, context, project_id=None):
        creds_info = get_credentials_using_credsmgr(
            context, project_id=project_id)
        neutron_credentials = {
            'aws_secret_access_key': creds_info['aws_secret_access_key'],
            'aws_access_key_id': creds_info['aws_access_key_id'],
            'region_name': aws_conf.region_name
        }
        ec2_client = boto3.client('ec2', **neutron_credentials)
        return ec2_client

    def _get_ec2_resource(self, context, project_id=None):
        creds_info = get_credentials_using_credsmgr(
            context, project_id=project_id)
        neutron_credentials = {
            'aws_secret_access_key': creds_info['aws_secret_access_key'],
            'aws_access_key_id': creds_info['aws_access_key_id'],
            'region_name': aws_conf.region_name
        }
        ec2_resource = boto3.resource('ec2', **neutron_credentials)
        return ec2_resource

    def create_resource_tags(self, resource, tags,
                             interval=None, timeout=None):
        if not interval:
            interval = self.interval
        if not timeout:
            timeout = self._wait_time_sec

        def run_func():
            try:
                resource.reload()
                LOG.debug('Adding tags %s on %s resources', str(tags),
                          str(resource))
                resource.create_tags(Tags=tags)
            except Exception:
                msg = 'Error while adding tags %s to resource %s.' \
                      ' Retrying...' % (tags, resource)
                LOG.debug(msg, exc_info=True)
                LOG.error(msg)
                return
            raise loopingcall.LoopingCallDone()
        timer = loopingcall.FixedIntervalWithTimeoutLoopingCall(run_func)
        timer.start(interval=interval, timeout=timeout).wait()

    # Internet Gateway Operations
    @aws_exception
    def get_internet_gw_from_router_id(self, router_id, context,
                                       dry_run=False, project_id=None):
        ig_id = omni_resources.get_omni_resource(router_id)
        if ig_id:
            LOG.debug('Found internet gateway ID in omni resources table %s',
                      ig_id)
            return ig_id
        response = self._get_ec2_client(
            context, project_id=project_id).describe_internet_gateways(
            DryRun=dry_run,
            Filters=[
                {
                    'Name': 'tag-value',
                    'Values': [router_id]
                },
            ]
        )
        if 'InternetGateways' in response:
            for internet_gateway in response['InternetGateways']:
                if 'InternetGatewayId' in internet_gateway:
                    ig_id = internet_gateway['InternetGatewayId']
                    omni_resources.add_mapping(router_id, ig_id)
                    return ig_id
        raise AwsException(
            error_code='404',
            message='Internet Gateway not found for router %s' % (router_id,))

    @aws_exception
    def create_tags_internet_gw_from_router_id(self, router_id, tags_list,
                                               context, dry_run=False):
        ig_id = self.get_internet_gw_from_router_id(router_id, context,
                                                    dry_run)
        internet_gw_res = self._get_ec2_resource(context).InternetGateway(
            ig_id)
        self.create_resource_tags(internet_gw_res, tags_list)

    @aws_exception
    def delete_internet_gateway(self, ig_id, context,
                                project_id=None, dry_run=False):
        self._get_ec2_client(
            context, project_id=project_id).delete_internet_gateway(
            DryRun=dry_run, InternetGatewayId=ig_id)

    @aws_exception
    def delete_internet_gateway_by_router_id(self, router_id, context,
                                             project_id=None,
                                             dry_run=False):
        try:
            ig_id = self.get_internet_gw_from_router_id(
                router_id, context, dry_run=dry_run, project_id=project_id)
        except AwsException as e:
            LOG.warn(e.message)
            return
        LOG.info('Deleting internet gateway - %s', ig_id)

        self._get_ec2_client(
            context, project_id=project_id).delete_internet_gateway(
            DryRun=dry_run, InternetGatewayId=ig_id)

    @aws_exception
    def attach_internet_gateway(self, ig_id, vpc_id, context, dry_run=False):
        LOG.info('Attaching internet gateway %s to VPC %s', ig_id, vpc_id)
        return self._get_ec2_client(context).attach_internet_gateway(
            DryRun=dry_run, InternetGatewayId=ig_id, VpcId=vpc_id)

    @aws_exception
    def detach_internet_gateway(self, ig_id, context,
                                project_id=None, dry_run=False):
        ig_res = self._get_ec2_resource(
            context, project_id=project_id).InternetGateway(ig_id)
        if len(ig_res.attachments) > 0:
            vpc_id = ig_res.attachments[0]['VpcId']
        self._get_ec2_client(
            context, project_id=project_id).detach_internet_gateway(
            DryRun=dry_run, InternetGatewayId=ig_id, VpcId=vpc_id)

    @aws_exception
    def detach_internet_gateway_by_router_id(self, router_id, context,
                                             project_id=None,
                                             dry_run=False):
        try:
            ig_id = self.get_internet_gw_from_router_id(
                router_id, context, project_id=project_id)
        except AwsException as e:
            LOG.error(e.message)
            return
        ig_res = self._get_ec2_resource(
            context, project_id=project_id).InternetGateway(ig_id)
        if len(ig_res.attachments) > 0:
            vpc_id = ig_res.attachments[0]['VpcId']
            LOG.info('Detaching internet gateway - %s', ig_id)
            self._get_ec2_client(
                context, project_id=project_id).detach_internet_gateway(
                DryRun=dry_run, InternetGatewayId=ig_id, VpcId=vpc_id)

    @aws_exception
    def create_internet_gateway_resource(self, context, dry_run=False):
        ec2_client = self._get_ec2_client(context)
        internet_gw = ec2_client.create_internet_gateway(
            DryRun=dry_run)
        ig_id = internet_gw['InternetGateway']['InternetGatewayId']
        LOG.info('Created %s internet gateway', ig_id)
        ec2_resource = self._get_ec2_resource(context)
        ig_resource = ec2_resource.InternetGateway(ig_id)
        return ig_resource

    # Elastic IP Operations
    @aws_exception
    def get_elastic_addresses_by_elastic_ip(self, elastic_ip, context,
                                            dry_run=False, project_id=None):
        eip_addresses = self._get_ec2_client(
            context, project_id=project_id).describe_addresses(
            DryRun=dry_run, PublicIps=[elastic_ip])
        return eip_addresses['Addresses']

    @aws_exception
    def associate_elastic_ip_to_ec2_instance(self, elastic_ip, ec2_instance_id,
                                             context, dry_run=False):
        allocation_id = None
        eid_addresses = self.get_elastic_addresses_by_elastic_ip(
            elastic_ip, context, dry_run)
        if len(eid_addresses) > 0:
            if 'AllocationId' in eid_addresses[0]:
                allocation_id = eid_addresses[0]['AllocationId']
        if allocation_id is None:
            raise AwsException(error_code="Allocation ID",
                               message="Allocation ID not found")
        LOG.info('Associating %s IP to %s instance', elastic_ip,
                 ec2_instance_id)
        return self._get_ec2_client(context).associate_address(
            DryRun=dry_run,
            InstanceId=ec2_instance_id,
            AllocationId=allocation_id
        )

    @aws_exception
    def allocate_elastic_ip(self, context, dry_run=False):
        LOG.debug('Creating new elastic IP')
        response = self._get_ec2_client(context).allocate_address(
            DryRun=dry_run,
            Domain='vpc'
        )
        LOG.info('Created new elastic IP - %s', response.get('PublicIp'))
        return response

    @aws_exception
    def disassociate_elastic_ip_from_ec2_instance(self, elastic_ip, context,
                                                  dry_run=False):
        association_id = None
        eid_addresses = self.get_elastic_addresses_by_elastic_ip(
            elastic_ip, context, dry_run)
        if len(eid_addresses) > 0:
            if 'AssociationId' in eid_addresses[0]:
                association_id = eid_addresses[0]['AssociationId']
        if association_id is None:
            raise AwsException(error_code="Association ID",
                               message="Association ID not found")
        LOG.info('Dissociating %s IP from instance', elastic_ip)
        return self._get_ec2_client(context).disassociate_address(
            DryRun=dry_run,
            AssociationId=association_id
        )

    @aws_exception
    def delete_elastic_ip(self, elastic_ip, context,
                          dry_run=False, project_id=None):
        eid_addresses = self.get_elastic_addresses_by_elastic_ip(
            elastic_ip, context, dry_run=dry_run, project_id=project_id)
        allocation_id = None
        if len(eid_addresses) > 0:
            if 'AllocationId' in eid_addresses[0]:
                allocation_id = eid_addresses[0]['AllocationId']
        if allocation_id is None:
            raise AwsException(error_code="Allocation ID",
                               message="Allocation ID not found")
        LOG.info('Releasing %s elastic IP', elastic_ip)
        return self._get_ec2_client(
            context, project_id=project_id).release_address(
            DryRun=dry_run, AllocationId=allocation_id)

    # VPC Operations
    @aws_exception
    def get_vpc_from_neutron_network_id(self, neutron_network_id, context,
                                        dry_run=False, project_id=None):
        vpc_id = omni_resources.get_omni_resource(neutron_network_id)
        if vpc_id:
            LOG.debug('Found %s VPC ID for %s network in neutron db', vpc_id,
                      neutron_network_id)
            return vpc_id
        ec2_client = self._get_ec2_client(context, project_id=project_id)
        LOG.debug('Querying AWS for VPC ID corresponding to %s network',
                  neutron_network_id)
        response = ec2_client.describe_vpcs(
            DryRun=dry_run,
            Filters=[
                {
                    'Name': 'tag-value',
                    'Values': [neutron_network_id]
                }
            ]
        )
        if 'Vpcs' in response:
            for vpc in response['Vpcs']:
                if 'VpcId' in vpc:
                    return vpc['VpcId']
        return None

    @aws_exception
    def create_vpc_and_tags(self, cidr, tags_list, context, dry_run=False):
        ec2_client = self._get_ec2_client(context)
        vpc_id = ec2_client.create_vpc(
            DryRun=dry_run,
            CidrBlock=cidr)['Vpc']['VpcId']
        LOG.info('Created VPC %s', vpc_id)
        vpc = self._get_ec2_resource(context).Vpc(vpc_id)
        self.create_resource_tags(vpc, tags_list)
        return vpc_id

    @aws_exception
    def delete_vpc(self, vpc_id, context, dry_run=False, project_id=None):
        LOG.info('Attempting to delete %s VPC', vpc_id)

        sg_id_list = self.get_sec_group_by_vpc_id(
            vpc_id, context, dry_run, project_id=project_id)
        for sg_id in sg_id_list:
            LOG.info('Deleting security group %s associated with %s VPC',
                     sg_id, vpc_id)
            self.delete_security_group_by_id(
                sg_id, context, project_id=project_id)
        LOG.debug('Deleting VPC %s', vpc_id)
        status = self._get_ec2_client(
            context, project_id=project_id).delete_vpc(
            DryRun=dry_run, VpcId=vpc_id)
        LOG.info('Deleted %s VPC', vpc_id)
        if not status:
            raise AwsException(
                error_code="Failed",
                message="Deletion of vpc %s" % (vpc_id,))


    @aws_exception
    def create_tags_for_vpc(self, neutron_network_id,
                            tags_list, context, project_id=None):
        LOG.info('Attempting to add tags on %s network', neutron_network_id)
        vpc_id = self.get_vpc_from_neutron_network_id(
            neutron_network_id, context, project_id=project_id)
        if vpc_id is not None:
            vpc = self._get_ec2_resource(
                context, project_id=project_id).Vpc(vpc_id)
            LOG.debug('Adding %s tags on %s network', str(tags_list), vpc_id)
            self.create_resource_tags(vpc, tags_list)
            LOG.info('Added tags on %s network', neutron_network_id)
        else:
            LOG.info('No VPC found corresponding to %s network.'
                     ' Skipped adding tags', neutron_network_id)

    # Subnet Operations
    @aws_exception
    def create_subnet_and_tags(self, vpc_id, cidr, tags_list,
                               aws_az, context, dry_run=False):
        ec2_resource = self._get_ec2_resource(context)
        vpc = ec2_resource.Vpc(vpc_id)
        LOG.info('Creating subnet in %s VPC with %s CIDR', vpc_id, cidr)
        subnet = vpc.create_subnet(
            AvailabilityZone=aws_az,
            DryRun=dry_run,
            CidrBlock=cidr)
        subnet = ec2_resource.Subnet(subnet.id)
        self.create_resource_tags(subnet, tags_list)
        LOG.info('Subnet creation successful - %s', subnet.id)
        return subnet.id

    @aws_exception
    def create_subnet_tags(self, neutron_subnet_id, tags_list, context,
                           dry_run=False, project_id=None):
        subnet_id = self.get_subnet_from_neutron_subnet_id(
            neutron_subnet_id, context, dry_run, project_id=project_id)
        subnet = self._get_ec2_resource(
            context, project_id=project_id).Subnet(subnet_id)
        LOG.debug('Adding %s tags to %s subnet', str(tags_list), subnet_id)
        self.create_resource_tags(subnet, tags_list)

    @aws_exception
    def delete_subnet(
            self, subnet_id, context, dry_run=False, project_id=None):
        ec2_client = self._get_ec2_client(context, project_id=project_id)
        LOG.info('Deleting subnet %s', subnet_id)
        status = ec2_client.delete_subnet(DryRun=dry_run, SubnetId=subnet_id)
        if not status:
            raise AwsException(
                error_code="Failed",
                message="Deletion of subnet %s" % (subnet_id,))

    @aws_exception
    def get_subnet_from_neutron_subnet_id(self, neutron_subnet_id, context,
                                          dry_run=False, project_id=None):
        subnet_id = omni_resources.get_omni_resource(neutron_subnet_id)
        LOG.debug('Fetching EC2 subnet ID for %s ID', neutron_subnet_id)
        if subnet_id:
            LOG.debug('Found %s associated with %s', subnet_id,
                      neutron_subnet_id)
            return subnet_id
        ec2_client = self._get_ec2_client(context, project_id=project_id)
        response = ec2_client.describe_subnets(
            DryRun=dry_run,
            Filters=[
                {
                    'Name': 'tag-value',
                    'Values': [neutron_subnet_id]
                }
            ]
        )
        if 'Subnets' in response:
            for subnet in response['Subnets']:
                if 'SubnetId' in subnet:
                    LOG.debug('Got %s subnet from EC2 with %s neutron ID',
                              subnet['SubnetId'], neutron_subnet_id)
                    return subnet['SubnetId']
        return None

    @aws_exception
    def get_subnet_from_vpc_and_cidr(self, context, vpc_id, cidr,
                                     project_id=None):
        LOG.debug('Fetching EC2 subnet for %s VPC with %s CIDR', vpc_id, cidr)
        ec2_client = self._get_ec2_client(context, project_id=project_id)
        response = ec2_client.describe_subnets(
            Filters=[
                {
                    'Name': 'vpc-id',
                    'Values': [vpc_id]
                },
                {
                    'Name': 'cidr',
                    'Values': [cidr]
                }
            ]
        )
        for subnet in response.get('Subnets', []):
            LOG.debug('Found subnets %s', subnet['SubnetId'])
            return subnet['SubnetId']
        return None

    @aws_exception
    def modify_ports(self, sgs, network_interface_name, context, project_id):
        ec2_client = self._get_ec2_client(context, project_id)
        ec2_client.modify_network_interface_attribute(
            Groups=sgs, NetworkInterfaceId=network_interface_name)

    # RouteTable Operations
    @aws_exception
    def describe_route_tables_by_vpc_id(self, vpc_id, context, dry_run=False):
        LOG.debug('Fetching route tables associated with %s', vpc_id)
        response = self._get_ec2_client(context).describe_route_tables(
            DryRun=dry_run,
            Filters=[
                {
                    'Name': 'vpc-id',
                    'Values': [vpc_id]
                },
            ]
        )
        return response['RouteTables']

    @aws_exception
    def get_route_table_by_router_id(self, neutron_router_id, context,
                                     dry_run=False, project_id=None):
        LOG.debug('Fetching route table ID for %s', neutron_router_id)

        response = self._get_ec2_client(
            context, project_id=project_id).describe_route_tables(
            DryRun=dry_run,
            Filters=[
                {
                    'Name': 'tag-value',
                    'Values': [neutron_router_id]
                },
            ]
        )
        return response['RouteTables']

    # Has ignore_errors special case so can't use decorator
    def create_default_route_to_ig(self, route_table_id, ig_id, context,
                                   dry_run=False, ignore_errors=False):
        try:
            LOG.info('Adding default route to IG %s using %s route table',
                     ig_id, route_table_id)
            resp = self._get_ec2_client(context).create_route(
                DryRun=dry_run, RouteTableId=route_table_id,
                DestinationCidrBlock='0.0.0.0/0', GatewayId=ig_id)
            if not resp['Return']:
                raise AwsException(
                    error_code="Failed",
                    message="Creation of route %s" % (route_table_id,))
        except Exception as e:
            LOG.warning("Ignoring failure in creating default route to IG: "
                        "%s" % e)
            if not ignore_errors:
                _process_exception(e, dry_run)

    # Has ignore_errors special case so can't use decorator
    def delete_default_route_to_ig(self, route_table_id, context,
                                   dry_run=False, ignore_errors=False,
                                   project_id=None):
        try:
            LOG.info('Deleting route table %s', route_table_id)
            status = self._get_ec2_client(
                context, project_id=project_id).delete_route(
                DryRun=dry_run,
                RouteTableId=route_table_id,
                DestinationCidrBlock='0.0.0.0/0'
            )
            if not status:
                raise AwsException(
                    error_code="Failed",
                    message="Deletion of route %s" % (route_table_id,))
        except Exception as e:
            if not ignore_errors:
                _process_exception(e, dry_run)
            else:
                LOG.warning("Ignoring failure in deleting default route to IG:"
                            " %s" % e)

    def _convert_openstack_rules_to_vpc(self, rules):
        ingress_rules = []
        egress_rules = []
        for rule in rules:
            rule_dict = {}
            if rule['protocol'] is None:
                rule_dict['IpProtocol'] = '-1'
                rule_dict['FromPort'] = -1
                rule_dict['ToPort'] = -1
            elif rule['protocol'].lower() == 'icmp':
                rule_dict['IpProtocol'] = 'icmp'
                rule_dict['ToPort'] = -1
                # AWS allows only 1 type of ICMP traffic in 1 rule
                # we choose the smaller of the port_min and port_max values
                icmp_rule = rule.get('port_range_min', '-1')
                if not icmp_rule:
                    # allow all ICMP traffic rule
                    icmp_rule = '-1'
                rule_dict['FromPort'] = int(icmp_rule)
            else:
                rule_dict['IpProtocol'] = rule['protocol']
                if rule['port_range_min'] is None:
                    rule_dict['FromPort'] = 0
                else:
                    rule_dict['FromPort'] = int(rule['port_range_min'])
                if rule['port_range_max'] is None:
                    rule_dict['ToPort'] = 65535
                else:
                    rule_dict['ToPort'] = int(rule['port_range_max'])
            if rule['ethertype'] == "IPv4":
                rule_dict['IpRanges'] = []
                if rule.get('remote_group_id') is not None:
                    rule_dict['IpRanges'].append({
                        'CidrIp': rule['remote_group_id']
                    })
                elif rule.get('remote_ip_prefix') is not None:
                    rule_dict['IpRanges'].append({
                        'CidrIp': str(rule['remote_ip_prefix'])
                    })
                else:
                    if rule['direction'] == 'egress':
                        if rule.get('remote_ip_prefix') is not None:
                            rule_dict['IpRanges'].append({
                                'CidrIp': str(rule['remote_ip_prefix'])
                            })
                        else:
                            # OpenStack does not populate allow all egress rule
                            # with remote_group_id or remote_ip_prefix keys.
                            rule_dict['IpRanges'].append({
                                'CidrIp': '0.0.0.0/0'
                            })
            elif rule['ethertype'] == "IPv6":
                LOG.warning("Ethertype IPv6 is supported only for EC2-VPC")
            if rule['direction'] == 'egress':
                egress_rules.append(rule_dict)
            else:
                ingress_rules.append(rule_dict)
        LOG.info('Converted [%s] rules as ingress - [%s] and egress - [%s]',
                 rules, ingress_rules, egress_rules)
        return ingress_rules, egress_rules

    def _refresh_sec_grp_rules(self, secgrp, ingress, egress):
        old_ingress = secgrp.ip_permissions
        old_egress = secgrp.ip_permissions_egress
        if not _is_same(old_ingress, ingress) and ingress:
            if old_ingress:
                LOG.info('Revoking ingress %s from %s', str(old_ingress),
                         secgrp.id)
                _run_ec2_sg_fn(secgrp.revoke_ingress,
                               IpPermissions=old_ingress)
                time.sleep(1)
            LOG.info('Authorizing %s to %s', str(ingress), secgrp.id)
            _run_ec2_sg_fn(secgrp.authorize_ingress, IpPermissions=ingress)
            time.sleep(1)
            secgrp.reload()
        if not _is_same(old_egress, egress) and egress:
            if old_egress:
                LOG.info('Revoking egress %s from %s', str(old_egress),
                         secgrp.id)
                _run_ec2_sg_fn(secgrp.revoke_egress, IpPermissions=old_egress)
                time.sleep(1)
            LOG.info('Authorizing %s to %s', str(egress), secgrp.id)
            _run_ec2_sg_fn(secgrp.authorize_egress, IpPermissions=egress)
            time.sleep(1)
            secgrp.reload()

    def _create_sec_grp_rules(self, secgrp, rules):
        ingress, egress = self._convert_openstack_rules_to_vpc(rules)

        def _wait_for_state(start_time):
            current_time = time.time()

            if current_time - start_time > self._wait_time_sec:
                raise loopingcall.LoopingCallDone(False)
            try:
                self._refresh_sec_grp_rules(secgrp, ingress, egress)
            except Exception:
                LOG.exception('Error creating security group rules. Retrying.')
                return
            raise loopingcall.LoopingCallDone(True)
        timer = loopingcall.FixedIntervalLoopingCall(_wait_for_state,
                                                     time.time())
        return timer.start(interval=self.interval).wait()

    def delete_security_group_rule_if_needed(self, context, secgrp_id,
                                             group_name, project_id, rule):
        ingress, egress = self._convert_openstack_rules_to_vpc([rule])
        aws_secgrps = self.get_sec_group_by_id(
            secgrp_id, context=context, project_id=project_id,
            group_name=group_name)
        sec_grp_ids = []
        changed = False
        for aws_secgrp in aws_secgrps:
            ec2_sg_id = aws_secgrp['GroupId']
            ec2_sg = self._get_ec2_resource(
                context, project_id=project_id).SecurityGroup(ec2_sg_id)
            sec_grp_ids.append(ec2_sg_id)
            if ingress and _is_present(aws_secgrp['IpPermissions'],
                                       ingress[0]):
                LOG.info('Revoking ingress %s from %s', str(ingress),
                         ec2_sg.id)
                _run_ec2_sg_fn(ec2_sg.revoke_ingress, IpPermissions=ingress)
                changed = True
            elif egress and _is_present(aws_secgrp['IpPermissionsEgress'],
                                        egress[0]):
                LOG.info('Revoking egress %s from %s', str(egress), ec2_sg.id)
                _run_ec2_sg_fn(ec2_sg.revoke_egress, IpPermissions=egress)
                changed = True
        if not changed:
            LOG.info('Security group %s updated but no corresponding security'
                     'group on AWS yet', secgrp_id)
            return
        self._update_sg_omni_res_mapping(context, project_id, sec_grp_ids,
                                         secgrp_id)

    def create_security_group_rule_if_needed(self, context, secgrp_id,
                                             group_name, project_id, rule):
        ingress, egress = self._convert_openstack_rules_to_vpc([rule])
        aws_secgrps = self.get_sec_group_by_id(
            secgrp_id, context=context, project_id=project_id,
            group_name=group_name)
        sec_grp_ids = []
        changed = False
        for aws_secgrp in aws_secgrps:
            ec2_sg_id = aws_secgrp['GroupId']
            ec2_sg = self._get_ec2_resource(
                context, project_id=project_id).SecurityGroup(ec2_sg_id)
            sec_grp_ids.append(ec2_sg_id)
            if ingress and not _is_present(aws_secgrp['IpPermissions'],
                                           ingress[0]):
                LOG.info('Authorizing %s from %s', str(ingress), ec2_sg.id)
                _run_ec2_sg_fn(ec2_sg.authorize_ingress, IpPermissions=ingress)
                changed = True
            elif egress and not _is_present(
                    aws_secgrp['IpPermissionsEgress'], egress[0]):
                LOG.info('Authorizing %s from %s', str(egress), ec2_sg.id)
                _run_ec2_sg_fn(ec2_sg.authorize_egress, IpPermissions=egress)
                changed = True
        if not changed:
            LOG.info('Security group %s updated but no corresponding security'
                     'group on AWS yet', secgrp_id)
            return
        self._update_sg_omni_res_mapping(context, project_id, sec_grp_ids,
                                         secgrp_id)

    def _update_sg_omni_res_mapping(self, context, project_id, sec_grp_ids,
                                    os_id):
        ec2client = self._get_ec2_client(context, project_id=project_id)
        updated_sgs = ec2client.describe_security_groups(GroupIds=sec_grp_ids)
        self._update_secgrp_mapping(os_id,
                                    updated_sgs.get('SecurityGroups', []))

    def create_security_group_rules(self, ec2_secgrp, rules):
        if self._create_sec_grp_rules(ec2_secgrp, rules) is False:
            raise AwsException(
                message='Timed out creating security groups',
                error_code='Time Out')

    def _filter_default_sec_groups(self, sec_groups):
        filtered = []
        for sec_group in sec_groups:
            if sec_group['GroupName'] != 'default':
                filtered.append(sec_group)
        return filtered

    def _update_secgrp_mapping(self, secgrp_id, aws_sec_groups, vpc_id=None):
        # In case no record was found default to empty dict
        filtered_sec_groups = self._filter_default_sec_groups(aws_sec_groups)
        resource_map = {}
        if vpc_id:
            db_resource_map = \
                omni_resources.get_omni_resource(secgrp_id) or '{}'
            resource_map = json.loads(db_resource_map)
            if len(filtered_sec_groups) == 1:
                resource_map[vpc_id] = filtered_sec_groups[0]
            else:
                # NO security groups present on AWS corresponding to
                # given OpenStack security group.
                return
        else:
            for aws_sec_group in filtered_sec_groups:
                resource_map[aws_sec_group['VpcId']] = aws_sec_group
            if len(resource_map) == 0:
                # NO security groups present on AWS corresponding to given
                # OpenStack security group.
                return
        omni_resources.add_mapping(secgrp_id, json.dumps(resource_map))

    def create_security_group(self, name, description, vpc_id, os_secgrp_id,
                              tags, context, project_id=None):
        if not description:
            description = 'Created by Platform9 OpenStack'
        ec2_resource = self._get_ec2_resource(context, project_id=project_id)
        secgrp = ec2_resource.create_security_group(
            GroupName=name, Description=description, VpcId=vpc_id)
        if self.create_resource_tags(secgrp, tags) is False:
            self.delete_security_group_by_id(
                secgrp.id, context, project_id=project_id)
            raise AwsException(
                message='Timed out creating tags on security group',
                error_code='Time Out')
        return secgrp

    @aws_exception
    def get_sec_group_by_vpc_id(
            self, vpc_id, context, dry_run=False, project_id=None):
        filters = [{'Name': 'vpc-id',
                    'Values': [vpc_id]}]
        ec2_client = self._get_ec2_client(context, project_id=project_id)
        response = ec2_client.describe_security_groups(
            DryRun=dry_run, Filters=filters)
        sg_id_list = []
        if 'SecurityGroups' in response:
            for sg in response['SecurityGroups']:
                if sg['GroupName'] != 'default':
                    sg_id_list.append(sg['GroupId'])
        return sg_id_list

    @aws_exception
    def get_sec_group_by_id(self, secgrp_id, context, group_name=None,
                            vpc_id=None, dry_run=False, project_id=None):
        secgrp_resource = omni_resources.get_omni_resource(secgrp_id)
        if secgrp_resource:
            sec_grp_obj = json.loads(secgrp_resource)
            if not vpc_id:
                return sec_grp_obj.values()
            if vpc_id in sec_grp_obj:
                return [sec_grp_obj.get(vpc_id, [])]
        else:
            sec_grp_obj = {}

        filters = [{'Name': 'tag-value',
                    'Values': [secgrp_id]}]
        if group_name:
            filters.append({'Name': 'group-name', 'Values': [group_name]})
        if vpc_id:
            filters.append({'Name': 'vpc-id', 'Values': [vpc_id]})
        ec2_client = self._get_ec2_client(context, project_id=project_id)
        response = ec2_client.describe_security_groups(
            DryRun=dry_run, Filters=filters)
        if 'SecurityGroups' in response and response['SecurityGroups']:
            self._update_secgrp_mapping(secgrp_id, response['SecurityGroups'],
                                        vpc_id=vpc_id)
            return self._filter_default_sec_groups(response['SecurityGroups'])

        # If security group was discovered it does not have openstack_id tag.
        filters = [elem for elem in filters if elem['Name'] != 'tag-value']

        # If no filters are left we will end up querying all security groups
        # and map it provided security group ID. Return from here to
        # avoid this case.
        if len(filters) == 0:
            return []
        ec2_client = self._get_ec2_client(context, project_id=project_id)
        response = ec2_client.describe_security_groups(
            DryRun=dry_run, Filters=filters)
        if 'SecurityGroups' in response:
            self._update_secgrp_mapping(secgrp_id, response['SecurityGroups'],
                                        vpc_id=vpc_id)
            return self._filter_default_sec_groups(response['SecurityGroups'])
        return []

    @aws_exception
    def delete_security_group(self, openstack_id, context, project_id=None,
                              group_name=None):
        aws_secgroups = self.get_sec_group_by_id(
            openstack_id, context, project_id=project_id,
            group_name=group_name)
        for secgrp in aws_secgroups:
            group_id = secgrp['GroupId']
            try:
                self.delete_security_group_by_id(
                    group_id, context, project_id=project_id)
            except Exception:
                LOG.warn('%s security group not found while deleting',
                         group_id)
        omni_resources.delete_mapping(openstack_id)

    @aws_exception
    def delete_security_group_by_id(self, group_id, context, project_id=None):
        ec2client = self._get_ec2_client(context, project_id=project_id)
        status = ec2client.delete_security_group(GroupId=group_id)
        if not status:
            raise AwsException(
                error_code="Failed",
                message="Deletion of security group %s" % (group_id,))

    @aws_exception
    def update_sec_group(self, openstack_id, rules, context, project_id=None,
                         group_name=None):
        ingress, egress = self._convert_openstack_rules_to_vpc(rules)
        aws_secgrps = self.get_sec_group_by_id(
            openstack_id, context=context, project_id=project_id,
            group_name=group_name)
        sec_grp_ids = []
        for aws_secgrp in aws_secgrps:
            ec2_sg_id = aws_secgrp['GroupId']
            ec2_sg = self._get_ec2_resource(
                context, project_id=project_id).SecurityGroup(ec2_sg_id)
            sec_grp_ids.append(ec2_sg_id)
            self._refresh_sec_grp_rules(ec2_sg, ingress, egress)
        if len(sec_grp_ids) == 0:
            LOG.info('Security group %s updated but no corresponding security'
                     'group on AWS yet', openstack_id)
            return
        ec2client = self._get_ec2_client(context, project_id=project_id)
        updated_sgs = ec2client.describe_security_groups(GroupIds=sec_grp_ids)
        updated_sg_resource = {sg['VpcId']: sg for sg in
                               updated_sgs.get('SecurityGroups', []) if
                               sg['GroupName'] != 'default'}
        omni_resources.add_mapping(openstack_id,
                                   json.dumps(updated_sg_resource))
