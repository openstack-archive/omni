"""
Copyright 2018 Platform9 Systems Inc.(http://www.platform9.com).

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
import datetime
import logging
import six

from neutron_lib.api.definitions import provider_net as providernet
from neutron_lib import context
from neutron_lib.plugins import directory

from neutron.common.aws_utils import AwsUtils
from neutron.extensions import availability_zone as az_ext
from neutron.plugins.ml2 import driver_api as api

LOG = logging.getLogger(__name__)


class SubnetExtensionDriver(api.ExtensionDriver):
    """Subnet extension driver to process and extend AZ data."""

    _supported_extension_alias = 'subnet_availability_zone'

    def initialize(self):
        """Initialize subnet extension driver."""
        self.subnet_cache = {}
        self.vpc_cidr_cache = {}
        self.aws_obj = AwsUtils()
        self.physical_network_cache = {}
        self.ec2_client_cache = {}
        self.ec2_cache_timer = datetime.datetime.now()
        self._ks_session = None
        LOG.info("SubnetExtensionDriver initialization complete")

    @property
    def ks_session(self):
        if self._ks_session is None:
            self._ks_session = self.aws_obj.get_keystone_session()
        return self._ks_session

    def get_context(self, project_id):
        ctx = context.Context(tenant_id=project_id)
        ctx.auth_token = self.ks_session.get_token()
        return ctx

    def get_ec2_client(self, project_id):
        tdiff = datetime.datetime.now() - self.ec2_cache_timer
        if tdiff.total_seconds() > 900:
            self.ec2_cache_timer = datetime.datetime.now()
            self.ec2_client_cache = {}
        if project_id in self.ec2_client_cache:
            return self.ec2_client_cache[project_id]
        ctx = self.get_context(project_id=project_id)
        ec2_client = self.aws_obj._get_ec2_client(ctx, project_id=project_id)
        self.ec2_client_cache[project_id] = ec2_client
        return ec2_client

    def _get_phynet_from_network(self, network_id, tenant_id):
        if network_id in self.physical_network_cache:
            return self.physical_network_cache[network_id]

        ctx = self.get_context(project_id=tenant_id)
        try:
            plugin = directory.get_plugin()
            network = plugin.get_network(ctx, network_id)
            if providernet.PHYSICAL_NETWORK in network:
                phy_net = network[providernet.PHYSICAL_NETWORK]
                self.physical_network_cache[network_id] = phy_net
                return phy_net
        except Exception as e:
            LOG.exception(e)
        return None

    @property
    def extension_alias(self):
        """Extension alias to load extension."""
        return self._supported_extension_alias

    def process_create_subnet(self, plugin_context, data, result):
        """Set AZ data in result to use in AWS mechanism."""
        result[az_ext.RESOURCE_NAME] = data[az_ext.RESOURCE_NAME]
        self.subnet_cache[result['id']] = data[az_ext.RESOURCE_NAME]

    def _check_for_vpc_cidr(self, vpc, result):
        cidr = result['cidr']
        if (vpc, cidr) in self.vpc_cidr_cache:
            result[az_ext.RESOURCE_NAME] = self.vpc_cidr_cache[(vpc, cidr)]
            return True
        project_id = result['tenant_id']
        ec2_client = self.get_ec2_client(project_id)
        response = ec2_client.describe_subnets(Filters=[
            {
                'Name': 'vpc-id',
                'Values': [vpc]
            }, ])
        if 'Subnets' in response:
            for subnet in response['Subnets']:
                self.vpc_cidr_cache[(subnet['VpcId'], subnet['CidrBlock'])] = \
                    subnet['AvailabilityZone']
        if (vpc, cidr) in self.vpc_cidr_cache:
            result[az_ext.RESOURCE_NAME] = self.vpc_cidr_cache[(vpc, cidr)]
            return True
        return False

    def _check_for_openstack_subnet(self, result):
        ostack_id = result['id']
        if ostack_id in self.subnet_cache:
            result[az_ext.RESOURCE_NAME] = self.subnet_cache[ostack_id]
            return True
        project_id = result['tenant_id']
        ec2_client = self.get_ec2_client(project_id)
        response = ec2_client.describe_subnets(Filters=[
            {
                'Name': 'tag-value',
                'Values': [ostack_id]
            }])
        if 'Subnets' in response:
            for subnet in response['Subnets']:
                if 'SubnetId' in subnet:
                    self.subnet_cache[ostack_id] = subnet['AvailabilityZone']
                    result[az_ext.RESOURCE_NAME] = subnet['AvailabilityZone']
                    return True
        return False

    def extend_subnet_dict(self, session, db_data, result):
        """Extend subnet dict."""
        phynet = self._get_phynet_from_network(
            result['network_id'], result['tenant_id'])
        if isinstance(phynet, six.string_types):
            if phynet == 'external':
                return
            elif phynet.startswith('vpc') and self._check_for_vpc_cidr(
                    phynet, result):
                return
        if self._check_for_openstack_subnet(result):
            return
