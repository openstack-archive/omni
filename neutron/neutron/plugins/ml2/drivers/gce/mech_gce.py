# Copyright 2017 Platform9 Systems Inc.(http://www.platform9.com)
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import random

from oslo_log import log

import ipaddr
from neutron._i18n import _
from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.common import gceconf
from neutron.common import gceutils
from neutron.manager import NeutronManager
from neutron.plugins.ml2 import driver_api as api
from neutron_lib import exceptions as e
from neutron.extensions import securitygroup as sg

LOG = log.getLogger(__name__)


class SecurityGroupInvalidDirection(e.InvalidInput):
    message = _("Security group rule for direction '%(direction)s' not "
                "supported. Allowed values are %(values)s.")


class GceMechanismDriver(api.MechanismDriver):
    """Ml2 Mechanism driver for GCE"""

    def __init__(self):
        super(GceMechanismDriver, self).__init__()
        self.gce_zone = gceconf.zone
        self.gce_region = gceconf.region
        self.gce_project = gceconf.project_id
        self.gce_svc_key = gceconf.service_key_path

    def initialize(self):
        self.gce_svc = gceutils.get_gce_service(self.gce_svc_key)
        LOG.info("GCE Mechanism driver init with %s project, %s region",
                 (self.gce_project, self.gce_region))
        self._subscribe_events()

    def _subscribe_events(self):
        registry.subscribe(self.secgroup_callback, resources.SECURITY_GROUP,
                           events.BEFORE_DELETE)
        registry.subscribe(self.secgroup_callback, resources.SECURITY_GROUP,
                           events.BEFORE_UPDATE)

        registry.subscribe(self.secgroup_callback,
                           resources.SECURITY_GROUP_RULE, events.BEFORE_DELETE)
        registry.subscribe(self.secgroup_callback,
                           resources.SECURITY_GROUP_RULE, events.BEFORE_UPDATE)

    def _gce_network_name(self, context):
        return 'net-' + context.current[api.ID]

    def _gce_subnet_name(self, context):
        return 'subnet-' + context.current[api.ID]

    def _gce_subnet_network_name(self, context):
        return 'net-' + context.current['network_id']

    @staticmethod
    def is_private_network(cidr):
        return ipaddr.IPNetwork(cidr).is_private

    def create_network_precommit(self, context):
        pass

    def create_network_postcommit(self, context):
        compute, project = self.gce_svc, self.gce_project
        name = self._gce_network_name(context)
        operation = gceutils.create_network(compute, project, name)
        gceutils.wait_for_operation(compute, project, operation)
        LOG.info('Created network on GCE %s', name)

    def update_network_precommit(self, context):
        pass

    def update_network_postcommit(self, context):
        pass

    def delete_network_precommit(self, context):
        pass

    def delete_network_postcommit(self, context):
        compute, project = self.gce_svc, self.gce_project
        name = self._gce_network_name(context)
        operation = gceutils.delete_network(compute, project, name)
        gceutils.wait_for_operation(compute, project, operation)
        LOG.info('Deleted network on GCE %s', name)

    def create_subnet_precommit(self, context):
        pass

    def create_subnet_postcommit(self, context):
        compute, project, region = self.gce_svc, self.gce_project, self.gce_region
        network_name = self._gce_subnet_network_name(context)
        name = self._gce_subnet_name(context)
        cidr = context.current['cidr']
        if self.is_private_network(cidr):
            network = gceutils.get_network(compute, project, network_name)
            network_link = network['selfLink']
            operation = gceutils.create_subnet(compute, project, region, name,
                                               cidr, network_link)
            gceutils.wait_for_operation(compute, project, operation)
            LOG.info("Created subnet %s in region %s on GCE", (name, region))

    def update_subnet_precommit(self, context):
        pass

    def update_subnet_postcommit(self, context):
        pass

    def delete_subnet_precommit(self, context):
        pass

    def delete_subnet_postcommit(self, context):
        compute, project, region = self.gce_svc, self.gce_project, self.gce_region
        cidr = context.current['cidr']
        if self.is_private_network(cidr):
            name = self._gce_subnet_name(context)
            operation = gceutils.delete_subnet(compute, project, region, name)
            gceutils.wait_for_operation(compute, project, operation)
            LOG.info("Deleted subnet %s in region %s on GCE",(name, region))

    def _gce_secgrp_id(self, openstack_id):
        return "secgrp-" + openstack_id

    def _convert_secgrp_rule_to_gce(self, rule, network_link):
        if rule['ethertype'] != 'IPv4':
            raise sg.SecurityGroupRuleInvalidEtherType(
                ethertype=rule['ethertype'], values=('IPv4', ))

        gce_rule = {
            'sourceRanges': [],
            'sourceTags': [],
            'targetTags': [],
            'allowed': [{}],
            'destinationRanges': [],
        }
        gce_rule['name'] = self._gce_secgrp_id(rule['id'])
        gce_rule['network'] = network_link

        directions = {
            'ingress': 'INGRESS',
        }
        gce_protocols = ('tcp', 'udp', 'icmp', 'esp', 'ah', 'sctp')

        if rule['direction'] in directions:
            gce_rule['direction'] = directions[rule['direction']]
        else:
            raise SecurityGroupInvalidDirection(direction=rule['direction'],
                                                values=directions.keys())

        protocol = rule['protocol']
        if protocol is None:
            gce_rule['allowed'][0]['IPProtocol'] = 'all'
        elif protocol in gce_protocols:
            gce_rule['allowed'][0]['IPProtocol'] = protocol
            # GCE allows port specification for tcp and udp only
            if protocol in ('tcp', 'udp'):
                ports = []
                port_range_max = rule['port_range_max']
                port_range_min = rule['port_range_min']
                if port_range_max is None or port_range_min is None:
                    ports.append('0-65535')
                elif port_range_max == port_range_min:
                    ports.append(str(port_range_max))
                else:
                    ports.append("%s-%s" % (port_range_min, port_range_max))
                gce_rule['allowed'][0]['ports'] = ports
        else:
            raise sg.SecurityGroupRuleInvalidProtocol(protocol=protocol,
                                                      values=gce_protocols)

        if rule['remote_ip_prefix'] is None:
            gce_rule['sourceRanges'].append('0.0.0.0/0')
        else:
            gce_rule['sourceRanges'].append(rule['remote_ip_prefix'])
        return gce_rule

    def _create_secgrp_rule(self, context, rule, network_link):
        compute, project = self.gce_svc, self.gce_project
        try:
            gce_rule = self._convert_secgrp_rule_to_gce(rule, network_link)
        except Exception as e:
            LOG.exception(
                "An error occured while creating security group: %s" % e)
            return
        LOG.info("Create GCE firewall rule %s", gce_rule)
        operation = gceutils.create_firewall_rule(compute, project, gce_rule)
        gceutils.wait_for_operation(compute, project, operation)

    def _update_secgrp_rule(self, context, rule_id):
        compute, project = self.gce_svc, self.gce_project
        name = self._gce_secgrp_id(rule_id)
        try:
            gce_firewall_info = gceutils.get_firewall_rule(
                compute, project, name)
        except gceutils.HttpError:
            return

        core_plugin = NeutronManager.get_plugin()
        rule = core_plugin.get_security_group_rule(context, rule_id)

        network_link = gce_firewall_info['network']
        try:
            gce_rule = self._convert_secgrp_rule_to_gce(rule, network_link)
            LOG.info("Update GCE firewall rule %s", name)
            operation = gceutils.update_firewall_rule(compute, project, name,
                                                      gce_rule)
            gceutils.wait_for_operation(compute, project, operation)
        except Exception as e:
            LOG.exception("An error occured while updating security "
                          "group: %s", e)
            LOG.error("Deleting existing GCE firewall rule %s", name)
            operation = gceutils.delete_firewall_rule(compute, project, name)
            gceutils.wait_for_operation(compute, project, operation)

    def _delete_secgrp_rule(self, context, rule_id):
        name = self._gce_secgrp_id(rule_id)
        compute, project = self.gce_svc, self.gce_project
        try:
            LOG.warn("Delete existing GCE firewall rule %s,"
                     "as firewall rule update not GCE compatible.", name)
            operation = gceutils.delete_firewall_rule(compute, project, name)
            gceutils.wait_for_operation(compute, project, operation)
        except gceutils.HttpError:
            pass

    def _create_secgrp_rules_if_needed(self, context, secgrp_ids):
        core_plugin = NeutronManager.get_plugin()
        secgrp_rules = []
        for secgrp_id in secgrp_ids:
            secgrp = core_plugin.get_security_group(context._plugin_context,
                                                    secgrp_id)
            secgrp_rules.extend(secgrp['security_group_rules'])
        if secgrp_rules:
            network_name = self._gce_subnet_network_name(context)
            compute, project = self.gce_svc, self.gce_project
            network = gceutils.get_network(compute, project, network_name)
            network_link = network['selfLink']
            for secgrp_rule in secgrp_rules:
                try:
                    gce_rule_name = self._gce_secgrp_id(secgrp_rule['id'])
                    gceutils.get_firewall_rule(compute, project, gce_rule_name)
                except gceutils.HttpError:
                    self._create_secgrp_rule(context, secgrp_rule,
                                             network_link)

    def _update_secgrp(self, context, secgrp_id):
        core_plugin = NeutronManager.get_plugin()
        secgrp = core_plugin.get_security_group(context, secgrp_id)
        secgrp_rules = secgrp['security_group_rules']
        for secgrp_rule in secgrp_rules:
            self._update_secgrp_rule(context, secgrp_rule['id'])

    def _delete_secgrp(self, context, secgrp_id):
        core_plugin = NeutronManager.get_plugin()
        secgrp = core_plugin.get_security_group(context, secgrp_id)
        secgrp_rules = secgrp['security_group_rules']
        for secgrp_rule in secgrp_rules:
            self._delete_secgrp_rule(context, secgrp_rule['id'])

    def bind_port(self, context):
        fixed_ip_dict = dict()
        if 'fixed_ips' in context.current:
            if len(context.current['fixed_ips']):
                fixed_ip_dict = context.current['fixed_ips'][0]
                secgrp_ids = context.current['security_groups']
                if secgrp_ids:
                    self._create_secgrp_rules_if_needed(context, secgrp_ids)

        segment_id = random.choice(context.segments_to_bind)[api.ID]
        context.set_binding(segment_id, "vip_type_a", fixed_ip_dict,
                            status='ACTIVE')
        return True

    def secgroup_callback(self, resource, event, trigger, **kwargs):
        if resource == resources.SECURITY_GROUP_RULE:
            context = kwargs['context']
            if event == events.BEFORE_DELETE:
                rule_id = kwargs['security_group_rule_id']
                self._delete_secgrp_rule(context, rule_id)
            elif event == events.BEFORE_UPDATE:
                rule_id = kwargs['security_group_rule_id']
                self._update_secgrp_rule(context, rule_id)
        elif resource == resources.SECURITY_GROUP:
            if event == events.BEFORE_DELETE:
                context = kwargs['context']
                security_group_id = kwargs.get('security_group_id')
                if security_group_id:
                    self._delete_secgrp(context, security_group_id)
                else:
                    LOG.warn("Security group ID not found in delete request")
