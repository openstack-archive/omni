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
import neutron_lib

from distutils.version import LooseVersion
from neutron.common.azure.config import azure_conf
from neutron.common.azure import utils
from neutron.db import common_db_mixin
from neutron.db import extraroute_db
from neutron.db import l3_db
from neutron.db import l3_dvrscheduler_db
from neutron.db import l3_gwmode_db
from neutron.db import l3_hamode_db
from neutron.db import l3_hascheduler_db
from neutron.plugins.common import constants
from neutron.quota import resource_registry
from neutron.services import service_base
from neutron_lib import constants as n_const
from oslo_log import log as logging

LOG = logging.getLogger(__name__)

if LooseVersion(neutron_lib.__version__) < LooseVersion("1.0.0"):
    router = l3_db.Router
    floating_ip = l3_db.FloatingIP
    plugin_type = constants.L3_ROUTER_NAT
    service_plugin_class = service_base.ServicePluginBase
else:
    from neutron.db.models import l3
    from neutron_lib.plugins import constants as plugin_constants
    from neutron_lib.services import base
    router = l3.Router
    floating_ip = l3.FloatingIP
    plugin_type = plugin_constants.L3
    service_plugin_class = base.ServicePluginBase


class AzureRouterPlugin(
        service_plugin_class, common_db_mixin.CommonDbMixin,
        extraroute_db.ExtraRoute_db_mixin, l3_hamode_db.L3_HA_NAT_db_mixin,
        l3_gwmode_db.L3_NAT_db_mixin, l3_dvrscheduler_db.L3_DVRsch_db_mixin,
        l3_hascheduler_db.L3_HA_scheduler_db_mixin):
    """Implementation of the Neutron L3 Router Service Plugin.

    This class implements a L3 service plugin that provides
    router and floatingip resources and manages associated
    request/response.
    All DB related work is implemented in classes
    l3_db.L3_NAT_db_mixin, l3_hamode_db.L3_HA_NAT_db_mixin,
    l3_dvr_db.L3_NAT_with_dvr_db_mixin, and extraroute_db.ExtraRoute_db_mixin.
    """
    supported_extension_aliases = [
        "dvr", "router", "ext-gw-mode", "extraroute", "l3_agent_scheduler",
        "l3-ha"
    ]

    @resource_registry.tracked_resources(router=router, floatingip=floating_ip)
    def __init__(self):
        super(AzureRouterPlugin, self).__init__()
        l3_db.subscribe()
        self._compute_client = None
        self._network_client = None
        self.tenant_id = azure_conf.tenant_id
        self.client_id = azure_conf.client_id
        self.client_secret = azure_conf.client_secret
        self.subscription_id = azure_conf.subscription_id
        self.region = azure_conf.region
        self.resource_group = azure_conf.resource_group

        LOG.info("Azure Router plugin init with %s project, %s region" %
                 (self.tenant_id, self.region))

    @property
    def compute_client(self):
        if self._compute_client is None:
            args = (self.tenant_id, self.client_id, self.client_secret,
                    self.subscription_id)
            self._compute_client = utils.get_compute_client(*args)
        return self._compute_client

    @property
    def network_client(self):
        if self._network_client is None:
            args = (self.tenant_id, self.client_id, self.client_secret,
                    self.subscription_id)
            self._network_client = utils.get_network_client(*args)
        return self._network_client

    def get_plugin_type(self):
        return plugin_type

    def get_plugin_description(self):
        """returns string description of the plugin."""
        return ("Azure L3 Router Service Plugin for basic L3 forwarding"
                " between (L2) Neutron networks and access to external"
                " networks via a NAT gateway.")

    def _add_floatingip_to_port(self, port_id, public_ip):
        net_svc = self.network_client
        resource_group = self.resource_group
        nic_name = 'nic-' + port_id
        nic = utils.get_nic(net_svc, resource_group, nic_name)
        nic.ip_configurations[0].public_ip_address = public_ip
        utils.update_nic(net_svc, resource_group, nic_name, nic)

    def _remove_floatingip_from_port(self, port_id):
        self._add_floatingip_to_port(port_id, public_ip=None)

    def create_floatingip(self, context, floatingip):
        net_svc = self.network_client
        resource_group = self.resource_group
        public_ip = None
        port_id = None
        status = n_const.FLOATINGIP_STATUS_DOWN
        try:
            floatingip_dict = floatingip['floatingip']
            public_ip = utils.allocate_floatingip(net_svc, resource_group,
                                                  self.region)
            LOG.info("Created Azure static IP %s" % public_ip.ip_address)
            floatingip_dict['floating_ip_address'] = public_ip.ip_address
            port_id = floatingip_dict['port_id']
            if port_id:
                self._add_floatingip_to_port(port_id, public_ip)
                status = n_const.FLOATINGIP_STATUS_ACTIVE
            res = super(AzureRouterPlugin, self).create_floatingip(
                context, floatingip, initial_status=status)
        except Exception as e:
            LOG.exception("Error in Creation/Allocating floating IP: %s" % e)
            if status == n_const.FLOATINGIP_STATUS_ACTIVE:
                self._remove_floatingip_from_port(port_id)
            if public_ip:
                utils.delete_floatingip(net_svc, resource_group,
                                        public_ip.name)
            raise e
        return res

    def update_floatingip(self, context, id, floatingip):
        net_svc = self.network_client
        resource_group = self.resource_group
        status = n_const.FLOATINGIP_STATUS_DOWN
        floatingip_dict = floatingip['floatingip']
        orig_floatingip = super(AzureRouterPlugin, self).get_floatingip(
            context, id)
        ip_address = orig_floatingip['floating_ip_address']
        port_id = floatingip_dict['port_id']
        if port_id:
            public_ip = utils.get_floatingip(net_svc, resource_group,
                                             ip_address)
            self._add_floatingip_to_port(port_id, public_ip)
            status = n_const.FLOATINGIP_STATUS_ACTIVE
        else:
            self._remove_floatingip_from_port(orig_floatingip['port_id'])
        floatingip_dict['status'] = status
        return super(AzureRouterPlugin, self).update_floatingip(
            context, id, floatingip)

    def delete_floatingip(self, context, id):
        net_svc = self.network_client
        resource_group = self.resource_group
        floating_ip = super(AzureRouterPlugin, self).get_floatingip(
            context, id)
        ip_address = floating_ip['floating_ip_address']
        public_ip = utils.get_floatingip(net_svc, resource_group, ip_address)
        port_id = floating_ip['port_id']
        if port_id:
            self._remove_floatingip_from_port(port_id)
        utils.delete_floatingip(net_svc, resource_group, public_ip.name)
        return super(AzureRouterPlugin, self).delete_floatingip(context, id)

    def create_router(self, context, router):
        LOG.debug("Creating router %s" % router['router']['name'])
        return super(AzureRouterPlugin, self).create_router(context, router)

    def delete_router(self, context, id):
        LOG.debug("Deleting router %s" % id)
        return super(AzureRouterPlugin, self).delete_router(context, id)

    def update_router(self, context, id, router):
        LOG.debug("Updating router %s" % id)
        return super(AzureRouterPlugin, self).update_router(
            context, id, router)

    def add_router_interface(self, context, router_id, interface_info):
        LOG.debug("Adding interface %s to router %s" % (interface_info,
                                                        router_id))
        return super(AzureRouterPlugin, self).add_router_interface(
            context, router_id, interface_info)

    def remove_router_interface(self, context, router_id, interface_info):
        LOG.debug("Deleting interface %s from router %s" % (interface_info,
                                                            router_id))
        return super(AzureRouterPlugin, self).remove_router_interface(
            context, router_id, interface_info)
