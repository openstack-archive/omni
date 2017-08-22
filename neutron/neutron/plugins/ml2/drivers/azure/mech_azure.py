"""
Copyright 2017 Platform9 Systems Inc.(http://www.platform9.com)
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

from neutron._i18n import _
from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.common.azconfig import azure_conf
from neutron.common import azutils
from neutron.extensions import securitygroup as sg
from neutron.manager import NeutronManager
from neutron.plugins.ml2 import driver_api as api
from neutron_lib import exceptions as e
from oslo_log import log

import ipaddr
import random

try:
    from neutron_lib.plugins import directory
except ImportError:
    pass

LOG = log.getLogger(__name__)


class SecurityGroupInvalidDirection(e.InvalidInput):
    message = _("Security group rule for direction '%(direction)s' not "
                "supported. Allowed values are %(values)s.")


def log_network_hook(function):
    def wraps(self, context):
        LOG.info("Called %s with context: %s" % (function.__name__, context))
        return function(self, context)
    return wraps


class AzureMechanismDriver(api.MechanismDriver):
    """Ml2 Mechanism driver for Azure"""

    def __init__(self):
        super(AzureMechanismDriver, self).__init__()
        self._network_client = None

    def initialize(self):
        LOG.info("Azure Mechanism driver init with %s project, %s region" %
                 (azure_conf.tenant_id, azure_conf.region))
        self._subscribe_events()

    def _subscribe_events(self):
        registry.subscribe(self.secgroup_callback, resources.SECURITY_GROUP,
                           events.BEFORE_DELETE)
        registry.subscribe(self.secgroup_callback, resources.SECURITY_GROUP,
                           events.BEFORE_UPDATE)
        registry.subscribe(self.secgroup_callback, resources.SECURITY_GROUP,
                           events.BEFORE_RESPONSE)

        registry.subscribe(self.secgroup_callback,
                           resources.SECURITY_GROUP_RULE, events.BEFORE_DELETE)
        registry.subscribe(self.secgroup_callback,
                           resources.SECURITY_GROUP_RULE, events.BEFORE_UPDATE)
        registry.subscribe(self.secgroup_callback,
                           resources.SECURITY_GROUP_RULE, events.BEFORE_CREATE)

    @property
    def network_client(self):
        conf = azure_conf
        if self._network_client is None:
            args = (conf.tenant_id, conf.client_id, conf.client_secret,
                    conf.subscription_id)
            self._network_client = azutils.get_network_client(*args)
        return self._network_client

    def _azure_network_name(self, context):
        return 'net-' + context.current[api.ID]

    def _azure_subnet_name(self, context):
        return 'subnet-' + context.current[api.ID]

    def _azure_subnet_network_name(self, context):
        return 'net-' + context.current['network_id']

    @staticmethod
    def is_private_network(cidr):
        return ipaddr.IPNetwork(cidr).is_private

    @log_network_hook
    def create_network_precommit(self, context):
        pass

    @log_network_hook
    def create_network_postcommit(self, context):
        pass

    @log_network_hook
    def update_network_precommit(self, context):
        pass

    @log_network_hook
    def update_network_postcommit(self, context):
        pass

    @log_network_hook
    def delete_network_precommit(self, context):
        pass

    @log_network_hook
    def delete_network_postcommit(self, context):
        name = self._azure_network_name(context)
        conf = azure_conf
        net_svc = self.network_client
        azutils.delete_network(net_svc, conf.resource_group, name)

    @log_network_hook
    def create_subnet_precommit(self, context):
        conf = azure_conf
        net_svc = self.network_client
        name = self._azure_subnet_name(context)
        network_name = self._azure_subnet_network_name(context)
        cidr = context.current['cidr']
        if self.is_private_network(cidr):
            try:
                az_network = azutils.get_network(net_svc, conf.resource_group,
                                                 network_name)
                LOG.info(az_network)
                # TODO(ssudake21): Handle case of network with multiple subnets
            except e.NetworkNotFound:
                body = {
                    'location': conf.region,
                    'address_space': {
                        'address_prefixes': [
                            cidr,
                        ]
                    }
                }
                azutils.create_network(net_svc, conf.resource_group,
                                       network_name, body)
            azutils.create_subnet(net_svc, conf.resource_group, network_name,
                                  name, {'address_prefix': cidr})

    @log_network_hook
    def create_subnet_postcommit(self, context):
        pass

    @log_network_hook
    def update_subnet_precommit(self, context):
        self.create_subnet_precommit(context)

    @log_network_hook
    def update_subnet_postcommit(self, context):
        pass

    @log_network_hook
    def delete_subnet_precommit(self, context):
        conf = azure_conf
        net_svc = self.network_client
        cidr = context.current['cidr']
        if self.is_private_network(cidr):
            name = self._azure_subnet_name(context)
            network_name = self._azure_subnet_network_name(context)
            azutils.delete_subnet(net_svc, conf.resource_group, network_name,
                                  name)

    @log_network_hook
    def delete_subnet_postcommit(self, context):
        # TODO(ssudake21): Delete network on azure if all subnets deleted
        pass

    def _create_secgrp_rule(self, context, rule, network_link):
        pass

    def _validate_secgrp_rule(self, rule):
        try:
            self._convert_secgrp_rule_to_gce(
                rule, network_link=None, validate=True)
        except SecurityGroupInvalidDirection:
            LOG.warn("Egress rules are not supported on GCE.")
            return
        except Exception as e:
            LOG.exception("An error occurred while creating security "
                          "group: %s" % e)
            raise e

    def _update_secgrp_rule(self, context, rule_id):
        pass

    def _delete_secgrp_rule(self, context, rule_id):
        pass

    def _create_secgrp_rules_if_needed(self, context, secgrp_ids):
        try:
            core_plugin = NeutronManager.get_plugin()
        except AttributeError:
            core_plugin = directory.get_plugin()
        secgrp_rules = []
        for secgrp_id in secgrp_ids:
            secgrp = core_plugin.get_security_group(context._plugin_context,
                                                    secgrp_id)
            secgrp_rules.extend(secgrp['security_group_rules'])
        if secgrp_rules:
            pass

    def _validate_secgrp(self, context, secgrp):
        secgrp_rules = secgrp['security_group_rules']
        try:
            for secgrp_rule in secgrp_rules:
                self._validate_secgrp_rule(secgrp_rule)
        except Exception as e:
            try:
                core_plugin = NeutronManager.get_plugin()
            except AttributeError:
                core_plugin = directory.get_plugin()
            LOG.info('Rollback create security group: %s' % secgrp['id'])
            core_plugin.delete_security_group(context, secgrp['id'])
            raise e

    def _update_secgrp(self, context, secgrp_id):
        try:
            core_plugin = NeutronManager.get_plugin()
        except AttributeError:
            core_plugin = directory.get_plugin()
        secgrp = core_plugin.get_security_group(context, secgrp_id)
        secgrp_rules = secgrp['security_group_rules']
        for secgrp_rule in secgrp_rules:
            self._update_secgrp_rule(context, secgrp_rule['id'])

    def _delete_secgrp(self, context, secgrp_id):
        try:
            core_plugin = NeutronManager.get_plugin()
        except AttributeError:
            core_plugin = directory.get_plugin()
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
        context.set_binding(
            segment_id, "vip_type_a", fixed_ip_dict, status='ACTIVE')
        return True

    def secgroup_callback(self, resource, event, trigger, **kwargs):
        LOG.debug("Secgrp_callback: %s %s %s" % (resource, event, kwargs))
        if resource == resources.SECURITY_GROUP_RULE:
            context = kwargs['context']
            if event == events.BEFORE_DELETE:
                rule_id = kwargs['security_group_rule_id']
                self._delete_secgrp_rule(context, rule_id)
            elif event == events.BEFORE_UPDATE:
                rule_id = kwargs['security_group_rule_id']
                self._update_secgrp_rule(context, rule_id)
            elif event == events.BEFORE_CREATE:
                rule = kwargs['security_group_rule']
                self._validate_secgrp_rule(rule)
        elif resource == resources.SECURITY_GROUP:
            if event == events.BEFORE_DELETE:
                context = kwargs['context']
                security_group_id = kwargs['security_group_id']
                self._delete_secgrp(context, security_group_id)
            elif event == events.BEFORE_RESPONSE:
                if kwargs['method_name'] == 'security_group.create.end':
                    context = kwargs['context']
                    secgrp = kwargs['data']['security_group']
                    self._validate_secgrp(context, secgrp)
