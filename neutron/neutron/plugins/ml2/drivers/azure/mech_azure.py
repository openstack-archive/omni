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

from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.common.azconfig import azure_conf
from neutron.common import azutils
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
                                               self._delete_secgrp_rule),
                       (resources.SECURITY_GROUP_RULE, events.BEFORE_UPDATE,
                        self._update_secgrp_rule),
                       (resources.SECURITY_GROUP_RULE, events.BEFORE_CREATE,
                        self._validate_secgrp_rule),
                       (resources.SECURITY_GROUP_RULE, events.AFTER_CREATE,
                        self._create_secgrp_rule)]
        for resource, event, callback in events_info:
            registry.subscribe(self.secgrp_callback, resource, event)
            self._sg_callback_map[(resource, event)] = callback

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

    @log_network_hook
    def create_port_precommit(self, context):
        net_svc = self.network_client
        resource_group = azure_conf.resource_group
        region = azure_conf.region
        network_name = self._azure_subnet_network_name(context)
        details = context.current['fixed_ips'][0]
        subnet_name = 'subnet-' + details['subnet_id']
        ip_address = details['ip_address']
        nic_name = 'nic-' + context.current['id']
        ipc_name = 'ipc-' + context.current['id']
        azure_subnet = azutils.get_subnet(net_svc, resource_group,
                                          network_name, subnet_name)
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
        azutils.create_nic(net_svc, resource_group, nic_name, body)
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
        net_svc = self.network_client
        resource_group = azure_conf.resource_group
        nic_name = 'nic-' + context.current['id']
        azutils.get_nic(net_svc, resource_group, nic_name)
        azutils.delete_nic(net_svc, resource_group, nic_name)
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

    def _validate_secgrp_rule(self, **kwargs):
        pass

    def _create_secgrp_rule(self, **kwargs):
        pass

    def _update_secgrp_rule(self, **kwargs):
        pass

    def _delete_secgrp_rule(self, **kwargs):
        pass

    def _validate_secgrp(self, **kwargs):
        pass

    def _create_secgrp(self, **kwargs):
        pass

    def _update_secgrp(self, **kwargs):
        pass

    def _delete_secgrp(self, **kwargs):
        pass

    def bind_port(self, context):
        fixed_ip_dict = dict()
        if 'fixed_ips' in context.current:
            if len(context.current['fixed_ips']):
                fixed_ip_dict = context.current['fixed_ips'][0]

        segment_id = random.choice(context.segments_to_bind)[api.ID]
        context.set_binding(
            segment_id, "vip_type_a", fixed_ip_dict, status='ACTIVE')
        return True

    def secgroup_callback(self, resource, event, trigger, **kwargs):
        LOG.info("Secgrp_callback: %s %s %s" % (resource, event, kwargs))
        callback = self._sg_callback_map[(resource, event)]
        callback(**kwargs)
