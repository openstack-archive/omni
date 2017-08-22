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

import random

from oslo_log import log

import ipaddr
from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.common.azure.config import azure_conf
from neutron.common.azure import utils
from neutron.manager import NeutronManager
from neutron.plugins.ml2 import driver_api as api
from neutron_lib import constants as n_const
from neutron_lib import exceptions as e

try:
    from neutron_lib.plugins import directory
except ImportError:
    pass

LOG = log.getLogger(__name__)


def log_network_hook(function):
    def wraps(self, context):
        LOG.debug("Called %s with context: %s" % (function.__name__, context))
        return function(self, context)

    return wraps


# Custom VIF type for Azure
VIF_TYPE_AZURE = "azure_nic"


class AzureMechanismDriver(api.MechanismDriver):
    """Ml2 Mechanism driver for Azure"""

    def __init__(self):
        super(AzureMechanismDriver, self).__init__()
        self._network_client = None
        self._sg_callback_map = {}

    def initialize(self):
        LOG.info("Azure Mechanism driver init with %s project, %s region" %
                 (azure_conf.tenant_id, azure_conf.region))
        self._subscribe_events()

    def _subscribe_events(self):
        events_info = [(resources.SECURITY_GROUP, events.BEFORE_DELETE,
                        self._delete_secgrp),
                       (resources.SECURITY_GROUP, events.BEFORE_UPDATE,
                        self._update_secgrp), (resources.SECURITY_GROUP,
                                               events.BEFORE_CREATE,
                                               self._validate_secgrp),
                       (resources.SECURITY_GROUP, events.AFTER_CREATE,
                        self._create_secgrp), (resources.SECURITY_GROUP_RULE,
                                               events.BEFORE_DELETE,
                                               self._delete_secrule),
                       (resources.SECURITY_GROUP_RULE, events.BEFORE_UPDATE,
                        self._update_secrule), (resources.SECURITY_GROUP_RULE,
                                                events.BEFORE_CREATE,
                                                self._validate_secrule),
                       (resources.SECURITY_GROUP_RULE, events.AFTER_CREATE,
                        self._create_secrule)]
        for resource, event, callback in events_info:
            registry.subscribe(self.secgrp_callback, resource, event)
            self._sg_callback_map[(resource, event)] = callback
        LOG.info("Azure mechanism driver registered security groups callbacks")

    @property
    def network_client(self):
        conf = azure_conf
        if self._network_client is None:
            args = (conf.tenant_id, conf.client_id, conf.client_secret,
                    conf.subscription_id)
            self._network_client = utils.get_network_client(*args)
        return self._network_client

    def _azure_network_name(self, context):
        return 'net-' + context.current[api.ID]

    def _azure_subnet_name(self, context):
        return 'subnet-' + context.current[api.ID]

    def _azure_subnet_network_name(self, context):
        return 'net-' + context.current['network_id']

    def _azure_secgrp_id(self, openstack_id):
        return "secgrp-" + openstack_id

    def _azure_secrule_id(self, openstack_id):
        return "secrule-" + openstack_id

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
        utils.delete_network(self.network_client, azure_conf.resource_group,
                             name)

    @log_network_hook
    def create_subnet_precommit(self, context):
        net_svc = self.network_client
        name = self._azure_subnet_name(context)
        network_name = self._azure_subnet_network_name(context)
        cidr = context.current['cidr']
        if self.is_private_network(cidr):
            try:
                azure_network = utils.get_network(
                    net_svc, azure_conf.resource_group, network_name)
                address_prefixes = azure_network.address_space.address_prefixes
                if cidr not in address_prefixes:
                    address_prefixes.append(cidr)
                    utils.update_network(net_svc, azure_conf.resource_group,
                                         network_name, azure_network)
            except e.NetworkNotFound:
                body = {
                    'location': azure_conf.region,
                    'address_space': {
                        'address_prefixes': [
                            cidr,
                        ]
                    }
                }
                utils.create_network(net_svc, azure_conf.resource_group,
                                     network_name, body)
            utils.create_subnet(net_svc, azure_conf.resource_group,
                                network_name, name, {'address_prefix': cidr})

    @log_network_hook
    def create_subnet_postcommit(self, context):
        pass

    @log_network_hook
    def update_subnet_precommit(self, context):
        pass

    @log_network_hook
    def update_subnet_postcommit(self, context):
        pass

    @log_network_hook
    def delete_subnet_precommit(self, context):
        cidr = context.current['cidr']
        if self.is_private_network(cidr):
            name = self._azure_subnet_name(context)
            network_name = self._azure_subnet_network_name(context)
            utils.delete_subnet(self.network_client, azure_conf.resource_group,
                                network_name, name)

    @log_network_hook
    def delete_subnet_postcommit(self, context):
        pass

    def _check_dev_owner(self, port_context):
        dev_owner = port_context.current['device_owner']
        return len(dev_owner) == 0 or dev_owner.startswith(
            n_const.DEVICE_OWNER_COMPUTE_PREFIX)

    @log_network_hook
    def create_port_precommit(self, context):
        LOG.debug("Create_port_precommit: %s" % context.current)
        if not self._check_dev_owner(context):
            return
        net_svc = self.network_client
        resource_group = azure_conf.resource_group
        region = azure_conf.region
        network_name = self._azure_subnet_network_name(context)
        details = context.current['fixed_ips'][0]
        subnet_name = 'subnet-' + details['subnet_id']
        ip_address = details['ip_address']
        nic_name = 'nic-' + context.current['id']
        ipc_name = 'ipc-' + context.current['id']
        azure_subnet = utils.get_subnet(net_svc, resource_group, network_name,
                                        subnet_name)
        body = {
            'location':
            region,
            'ip_configurations': [{
                'name': ipc_name,
                'private_ip_address': ip_address,
                'private_ip_allocation_method': 'Static',
                'subnet': {
                    'id': azure_subnet.id
                },
            }]
        }
        security_groups = context.current['security_groups']
        if security_groups and len(security_groups) == 1:
            sg_name = self._azure_secgrp_id(security_groups[0])
            sg = utils.get_sg(net_svc, resource_group, sg_name)
            body['network_security_group'] = {'id': sg.id}
        utils.create_nic(net_svc, resource_group, nic_name, body)
        LOG.info("Created NIC %s on Azure." % nic_name)

    @log_network_hook
    def create_port_postcommit(self, context):
        pass

    @log_network_hook
    def update_port_precommit(self, context):
        pass

    @log_network_hook
    def update_port_postcommit(self, context):
        pass

    @log_network_hook
    def delete_port_precommit(self, context):
        if not self._check_dev_owner(context):
            return
        net_svc = self.network_client
        resource_group = azure_conf.resource_group
        nic_name = 'nic-' + context.current['id']
        utils.get_nic(net_svc, resource_group, nic_name)
        utils.delete_nic(net_svc, resource_group, nic_name)
        LOG.info("Deleted NIC %s on Azure." % nic_name)

    @log_network_hook
    def delete_port_postcommit(self, context):
        pass

    def get_secgrp(self, context, id):
        try:
            core_plugin = NeutronManager.get_plugin()
        except AttributeError:
            core_plugin = directory.get_plugin()
        return core_plugin.get_security_group(context, id)

    def get_secgrp_rule(self, context, id):
        try:
            core_plugin = NeutronManager.get_plugin()
        except AttributeError:
            core_plugin = directory.get_plugin()
        return core_plugin.get_security_group_rule(context, id)

    def _validate_secrule(self, **kwargs):
        rule = kwargs['security_group_rule']
        utils.convert_sg_rule(rule)

    def _create_secrule(self, **kwargs):
        net_svc = self.network_client
        resource_group = azure_conf.resource_group
        rule = kwargs['security_group_rule']
        azure_rule = utils.convert_sg_rule(rule)
        sg_name = self._azure_secgrp_id(rule['security_group_id'])
        name = self._azure_secrule_id(rule['id'])
        sg = utils.get_sg(net_svc, resource_group, sg_name)
        """Each Azure security rule has a priority.
        The value can be between 100 and 4096. The priority number must be
        unique for each rule in the collection. The lower the priority number,
        the higher the priority of the rule.
        """
        previous_priorities = sorted([i.priority for i in sg.security_rules])
        if previous_priorities:
            priority = previous_priorities[-1] + 1
        else:
            priority = 100
        azure_rule['priority'] = priority
        utils.create_sg_rule(net_svc, resource_group, sg_name, name,
                             azure_rule)

    def _update_secrule(self, **kwargs):
        pass

    def _delete_secrule(self, **kwargs):
        net_svc = self.network_client
        resource_group = azure_conf.resource_group
        secrule_id = kwargs['security_group_rule_id']
        sec_rule = self.get_secgrp_rule(kwargs['context'], secrule_id)
        sg_name = self._azure_secgrp_id(sec_rule['security_group_id'])
        name = self._azure_secrule_id(secrule_id)
        utils.delete_sg_rule(net_svc, resource_group, sg_name, name)

    def _validate_secgrp(self, **kwargs):
        pass

    def _create_secgrp(self, **kwargs):
        net_svc = self.network_client
        resource_group = azure_conf.resource_group
        region = azure_conf.region
        name = self._azure_secgrp_id(kwargs['security_group']['id'])
        body = {
            'location': region,
        }
        utils.create_sg(net_svc, resource_group, name, body)

    def _update_secgrp(self, **kwargs):
        pass

    def _delete_secgrp(self, **kwargs):
        net_svc = self.network_client
        resource_group = azure_conf.resource_group
        name = self._azure_secgrp_id(kwargs['security_group_id'])
        utils.delete_sg(net_svc, resource_group, name)

    @log_network_hook
    def bind_port(self, context):
        fixed_ip_dict = dict()
        if 'fixed_ips' in context.current:
            if len(context.current['fixed_ips']):
                fixed_ip_dict = context.current['fixed_ips'][0]

        segment_id = random.choice(context.segments_to_bind)[api.ID]
        context.set_binding(
            segment_id, VIF_TYPE_AZURE, fixed_ip_dict, status='ACTIVE')
        return True

    def secgrp_callback(self, resource, event, trigger, **kwargs):
        LOG.info("Secgrp_callback: %s %s %s" % (resource, event, kwargs))
        callback = self._sg_callback_map[(resource, event)]
        callback(**kwargs)
