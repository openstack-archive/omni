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
import random

import requests
import six

from neutron.callbacks import events
from neutron.callbacks import resources
from neutron.common.aws_utils import AwsException
from neutron.common.aws_utils import AwsUtils
from neutron.db import omni_resources
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers.aws import callbacks
from neutron_lib import exceptions
from neutron_lib.plugins import directory

from oslo_config import cfg
from oslo_log import log

LOG = log.getLogger(__name__)

AZ = 'availability_zone'
AZ_HINT = 'availability_zone_hints'


class NetworkWithMultipleAZs(exceptions.NeutronException):
    message = "Network shouldn't have more than one availability zone"


class AzNotProvided(exceptions.NeutronException):
    """Raise exception if AZ is not provided in subnet or network."""

    message = "No AZ provided either in Subnet or in Network context"


class InvalidAzValue(exceptions.NeutronException):
    """Raise exception if AZ value is incorrect."""

    message = ("Invalid AZ value. It should be a single string value and from"
               " provided AWS region")


class AwsMechanismDriver(api.MechanismDriver):
    """Ml2 Mechanism driver for AWS"""
    def __init__(self):
        self.aws_utils = None
        self._default_sgr_to_remove = []
        super(AwsMechanismDriver, self).__init__()

    def initialize(self):
        self.aws_utils = AwsUtils()
        callbacks.subscribe(self)

    # NETWORK
    def create_network_precommit(self, context):
        pass

    def create_network_postcommit(self, context):
        pass

    def update_network_precommit(self, context):
        try:
            network_name = context.current['name']
            original_network_name = context.original['name']
            LOG.debug("Update network original: %s current: %s",
                      original_network_name, network_name)

            if network_name == original_network_name:
                return
            neutron_network_id = context.current['id']
            project_id = context.current['project_id']
            tags_list = [{'Key': 'Name', 'Value': network_name}]
            self.aws_utils.create_tags_for_vpc(neutron_network_id, tags_list,
                                               context=context._plugin_context,
                                               project_id=project_id)
        except Exception as e:
            LOG.error("Error in update subnet precommit: %s" % e)
            raise e

    def update_network_postcommit(self, context):
        pass

    def delete_network_precommit(self, context):
        neutron_network_id = context.current['id']
        project_id = context.current['project_id']
        # If user is deleting an empty  neutron network then nothing to be done
        # on AWS side
        if len(context.current['subnets']) > 0:
            vpc_id = self.aws_utils.get_vpc_from_neutron_network_id(
                neutron_network_id, context=context._plugin_context,
                project_id=project_id)
            if vpc_id is not None:
                LOG.info("Deleting network %s (VPC_ID: %s)" %
                         (neutron_network_id, vpc_id))
                try:
                    self.aws_utils.delete_vpc(vpc_id=vpc_id,
                                              context=context._plugin_context,
                                              project_id=project_id)
                except AwsException as e:
                    if 'InvalidVpcID.NotFound' in e.msg:
                        LOG.warn(e.msg)
                    else:
                        raise e
                omni_resources.delete_mapping(context.current['id'])

    def delete_network_postcommit(self, context):
        pass

    # SUBNET
    def create_subnet_precommit(self, context):
        network_id = context.network.current['id']
        LOG.info("Create subnet for network %s" % network_id)
        # External Network doesn't exist on AWS, so no operations permitted
        physical_network = context.network.current.get(
            'provider:physical_network')
        if physical_network == "external":
            # Do not create subnets for external & provider networks. Only
            # allow tenant network subnet creation at the moment.
            LOG.info('Creating external network {0}'.format(
                network_id))
            return
        elif physical_network and physical_network.startswith('vpc'):
            LOG.info('Registering AWS network with vpc %s',
                     physical_network)
            subnet_cidr = context.current['cidr']
            subnet_id = self.aws_utils.get_subnet_from_vpc_and_cidr(
                context._plugin_context, physical_network, subnet_cidr,
                context.current['project_id'])
            omni_resources.add_mapping(network_id, physical_network)
            omni_resources.add_mapping(context.current['id'], subnet_id)
            return
        if context.current['ip_version'] == 6:
            raise AwsException(error_code="IPv6Error",
                               message="Cannot create subnets with IPv6")
        mask = int(context.current['cidr'][-2:])
        if mask < 16 or mask > 28:
            raise AwsException(error_code="InvalidMask",
                               message="Subnet mask has to be >16 and <28")
        try:
            # Check if this is the first subnet to be added to a network
            neutron_network = context.network.current
            associated_vpc_id = self.aws_utils.get_vpc_from_neutron_network_id(
                neutron_network['id'], context=context._plugin_context)
            if associated_vpc_id is None:
                # Need to create EC2 VPC
                vpc_cidr = context.current['cidr'][:-2] + '16'
                tags = [
                    {'Key': 'Name', 'Value': neutron_network['name']},
                    {'Key': 'openstack_network_id',
                     'Value': neutron_network['id']},
                    {'Key': 'openstack_tenant_id',
                     'Value': context.current['tenant_id']}
                ]
                associated_vpc_id = self.aws_utils.create_vpc_and_tags(
                    cidr=vpc_cidr, tags_list=tags,
                    context=context._plugin_context)
                omni_resources.add_mapping(neutron_network['id'],
                                           associated_vpc_id)
            # Create Subnet in AWS
            tags = [
                {'Key': 'Name', 'Value': context.current['name']},
                {'Key': 'openstack_subnet_id', 'Value': context.current['id']},
                {'Key': 'openstack_tenant_id',
                 'Value': context.current['tenant_id']}
            ]
            if AZ in context.current and context.current[AZ]:
                aws_az = context.current[AZ]
            elif context.network.current[AZ_HINT]:
                network_az_hints = context.network.current[AZ_HINT]
                if len(network_az_hints) > 1:
                    # We use only one AZ hint even if multiple AZ values
                    # are passed while creating network.
                    raise NetworkWithMultipleAZs()
                aws_az = network_az_hints[0]
            else:
                raise AzNotProvided()
            self._validate_az(aws_az)
            ec2_subnet_id = self.aws_utils.create_subnet_and_tags(
                vpc_id=associated_vpc_id, cidr=context.current['cidr'],
                tags_list=tags, aws_az=aws_az, context=context._plugin_context)
            omni_resources.add_mapping(context.current['id'], ec2_subnet_id)
        except Exception as e:
            LOG.error("Error in create subnet precommit: %s" % e)
            raise e

    def _send_request(self, session, url):
        headers = {'Content-Type': 'application/json',
                   'X-Auth-Token': session.get_token()}
        response = requests.get(url + "/v1/zones", headers=headers)
        response.raise_for_status()
        return response.json()

    def _validate_az(self, aws_az):
        if not isinstance(aws_az, six.string_types):
            raise InvalidAzValue()
        if ',' in aws_az:
            raise NetworkWithMultipleAZs()
        session = self.aws_utils.get_keystone_session()
        azmgr_url = session.get_endpoint(service_type='azmanager',
                                         region_name=cfg.CONF.nova_region_name)
        zones = self._send_request(session, azmgr_url)
        if aws_az not in zones:
            LOG.error("Provided az %s not found in zones %s", aws_az, zones)
            raise InvalidAzValue()

    def create_subnet_postcommit(self, context):
        pass

    def update_subnet_precommit(self, context):
        try:
            subnet_name = context.current['name']
            neutron_subnet_id = context.current['id']
            tags_list = [{'Key': 'Name', 'Value': subnet_name}]
            self.aws_utils.create_subnet_tags(neutron_subnet_id, tags_list,
                                              context=context._plugin_context)
        except Exception as e:
            LOG.error("Error in update subnet precommit: %s" % e)
            raise e

    def update_subnet_postcommit(self, context):
        pass

    def delete_subnet_precommit(self, context):
        try:
            LOG.info("Deleting subnet %s" % context.current['id'])
            project_id = context.current['project_id']
            subnet_id = self.aws_utils.get_subnet_from_neutron_subnet_id(
                context.current['id'], context=context._plugin_context,
                project_id=project_id)
            if not subnet_id:
                raise Exception("Subnet mapping %s not found" % (
                    context.current['id']))
            try:
                self.aws_utils.delete_subnet(
                    subnet_id=subnet_id, context=context._plugin_context,
                    project_id=project_id)
                omni_resources.delete_mapping(context.current['id'])
            except AwsException as e:
                if 'InvalidSubnetID.NotFound' in e.msg:
                    LOG.warn(e.msg)
                    omni_resources.delete_mapping(context.current['id'])
                else:
                    raise e
        except Exception as e:
            LOG.error("Error in delete subnet precommit: %s" % e)
            raise e

    def delete_subnet_postcommit(self, context):
        neutron_network = context.network.current
        try:
            subnets = neutron_network['subnets']
            if (len(subnets) == 1 and subnets[0] == context.current['id'] or
                    len(subnets) == 0):
                # Last subnet for this network was deleted, so delete VPC
                # because VPC gets created during first subnet creation under
                # an OpenStack network
                project_id = context.current['project_id']
                vpc_id = self.aws_utils.get_vpc_from_neutron_network_id(
                    neutron_network['id'], context=context._plugin_context,
                    project_id=project_id)
                if not vpc_id:
                    raise Exception("Network mapping %s not found",
                                    neutron_network['id'])
                LOG.info("Deleting VPC %s since this was the last subnet in "
                         "the vpc" % vpc_id)
                self.aws_utils.delete_vpc(
                    vpc_id=vpc_id, context=context._plugin_context,
                    project_id=project_id)
                omni_resources.delete_mapping(context.network.current['id'])
        except Exception as e:
            LOG.error("Error in delete subnet postcommit: %s" % e)
            raise e

    def create_port_precommit(self, context):
        pass

    def create_port_postcommit(self, context):
        pass

    def update_port_precommit(self, context):
        original_port = context._original_port
        updated_port = context._port
        sorted_original_sgs = sorted(original_port['security_groups'])
        sorted_updated_sgs = sorted(updated_port['security_groups'])
        aws_sgs = []
        project_id = context.current['project_id']
        if sorted_updated_sgs != sorted_original_sgs:
            for sg in updated_port['security_groups']:
                aws_secgrps = self.aws_utils.get_sec_group_by_id(
                    sg, context._plugin_context, project_id=project_id)
                aws_sgs.append(aws_secgrps[0]['GroupId'])
        if aws_sgs:
            self.aws_utils.modify_ports(aws_sgs, updated_port['name'],
                                        context._plugin_context, project_id)

    def update_port_postcommit(self, context):
        pass

    def delete_port_precommit(self, context):
        pass

    def delete_port_postcommit(self, context):
        pass

    def bind_port(self, context):
        fixed_ip_dict = dict()
        if 'fixed_ips' in context.current:
            if len(context.current['fixed_ips']) > 0:
                fixed_ip_dict = context.current['fixed_ips'][0]
                openstack_subnet_id = fixed_ip_dict['subnet_id']
                aws_subnet_id = \
                    self.aws_utils.get_subnet_from_neutron_subnet_id(
                        openstack_subnet_id, context._plugin_context,
                        project_id=context.current['project_id'])
                fixed_ip_dict['subnet_id'] = aws_subnet_id
                secgroup_ids = context.current['security_groups']
                ec2_secgroup_ids = self.create_security_groups_if_needed(
                    context, secgroup_ids)
                fixed_ip_dict['ec2_security_groups'] = ec2_secgroup_ids
        segment_id = random.choice(context.network.network_segments)[api.ID]
        context.set_binding(segment_id, "vip_type_a",
                            json.dumps(fixed_ip_dict), status='ACTIVE')
        return True

    def create_security_groups_if_needed(self, context, secgrp_ids):
        project_id = context.current.get('project_id')
        core_plugin = directory.get_plugin()
        vpc_id = self.aws_utils.get_vpc_from_neutron_network_id(
            context.current['network_id'], context=context._plugin_context,
            project_id=project_id)
        ec2_secgroup_ids = []
        for secgrp_id in secgrp_ids:
            tags = [
                {'Key': 'openstack_id', 'Value': secgrp_id},
                {'Key': 'openstack_network_id',
                 'Value': context.current['network_id']}
            ]
            secgrp = core_plugin.get_security_group(context._plugin_context,
                                                    secgrp_id)
            aws_secgrps = self.aws_utils.get_sec_group_by_id(
                secgrp_id, group_name=secgrp['name'], vpc_id=vpc_id,
                context=context._plugin_context, project_id=project_id)
            if not aws_secgrps and secgrp['name'] != 'default':
                grp_name = secgrp['name']
                tags.append({"Key": "Name", "Value": grp_name})
                desc = secgrp['description']
                rules = secgrp['security_group_rules']
                ec2_secgrp = self.aws_utils.create_security_group(
                    grp_name, desc, vpc_id, secgrp_id, tags,
                    context=context._plugin_context,
                    project_id=project_id
                )
                self.aws_utils.create_security_group_rules(ec2_secgrp, rules)
                # Make sure that omni_resources table is populated with newly
                # created security group
                aws_secgrps = self.aws_utils.get_sec_group_by_id(
                    secgrp_id, group_name=secgrp['name'], vpc_id=vpc_id,
                    context=context._plugin_context, project_id=project_id)
            for aws_secgrp in aws_secgrps:
                ec2_secgroup_ids.append(aws_secgrp['GroupId'])
        return ec2_secgroup_ids

    def delete_security_group(self, security_group_id, context, project_id):
        core_plugin = directory.get_plugin()
        secgrp = core_plugin.get_security_group(context, security_group_id)
        self.aws_utils.delete_security_group(security_group_id, context,
                                             project_id,
                                             group_name=secgrp['name'])

    def remove_security_group_rule(self, context, rule_id):
        core_plugin = directory.get_plugin()
        rule = core_plugin.get_security_group_rule(context, rule_id)
        secgrp_id = rule['security_group_id']
        secgrp = core_plugin.get_security_group(context, secgrp_id)
        if "project_id" in rule:
            project_id = rule['project_id']
        else:
            project_id = context.tenant
        self.aws_utils.delete_security_group_rule_if_needed(
            context, secgrp_id, secgrp['name'], project_id, rule)

    def add_security_group_rule(self, context, rule):
        core_plugin = directory.get_plugin()
        secgrp_id = rule['security_group_id']
        secgrp = core_plugin.get_security_group(context, secgrp_id)
        if "project_id" in rule:
            project_id = rule['project_id']
        else:
            project_id = context.tenant
        self.aws_utils.create_security_group_rule_if_needed(
            context, secgrp_id, secgrp['name'], project_id, rule)

    def update_security_group_rules(self, context, rule_id):
        core_plugin = directory.get_plugin()
        rule = core_plugin.get_security_group_rule(context, rule_id)
        secgrp_id = rule['security_group_id']
        secgrp = core_plugin.get_security_group(context, secgrp_id)
        old_rules = secgrp['security_group_rules']
        for idx in range(len(old_rules) - 1, -1, -1):
            if old_rules[idx]['id'] == rule_id:
                old_rules.pop(idx)
                break
        old_rules.append(rule)
        if "project_id" in rule:
            project_id = rule['project_id']
        else:
            project_id = context.tenant
        self.aws_utils.update_sec_group(secgrp_id, old_rules, context=context,
                                        project_id=project_id,
                                        group_name=secgrp['name'])

    def secgroup_callback(self, resource, event, trigger, **kwargs):
        context = kwargs['context']
        if resource == resources.SECURITY_GROUP:
            if event == events.AFTER_CREATE:
                project_id = kwargs.get('security_group')['project_id']
                secgrp = kwargs.get('security_group')
                security_group_id = secgrp.get('id')
                core_plugin = directory.get_plugin()
                aws_secgrps = self.aws_utils.get_sec_group_by_id(
                    security_group_id, group_name=secgrp.get('name'),
                    context=context, project_id=project_id)
                if len(aws_secgrps) == 0:
                    return
                for sgr in secgrp.get('security_group_rules', []):
                    # This is invoked for discovered security groups only. For
                    # discovered security groups we do not need default egress
                    # rules. Those should be reported by discovery service.
                    # When removing these default security group rules we do
                    # not need to check against AWS. Store the security group
                    # rule IDs so that we can ignore them when delete security
                    # group rule is called here.
                    self._default_sgr_to_remove.append(sgr.get('id'))
                    core_plugin.delete_security_group_rule(context,
                                                           sgr.get('id'))
            if event == events.BEFORE_DELETE:
                project_id = kwargs.get('security_group')['project_id']
                security_group_id = kwargs.get('security_group_id')
                if security_group_id:
                    self.delete_security_group(security_group_id, context,
                                               project_id)
                else:
                    LOG.warn('Security group ID not found in delete request')
        elif resource == resources.SECURITY_GROUP_RULE:
            if event == events.BEFORE_CREATE:
                rule = kwargs['security_group_rule']
                self.add_security_group_rule(context, rule)
            elif event == events.BEFORE_DELETE:
                rule_id = kwargs['security_group_rule_id']
                if rule_id in self._default_sgr_to_remove:
                    # Check the comment above in security group rule
                    # AFTER_CREATE event handling
                    self._default_sgr_to_remove.remove(rule_id)
                else:
                    self.remove_security_group_rule(context, rule_id)
            elif event == events.BEFORE_UPDATE:
                rule_id = kwargs['security_group_rule_id']
                self.update_security_group_rules(context, rule_id)
