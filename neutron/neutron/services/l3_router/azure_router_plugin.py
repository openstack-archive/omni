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
from neutron.common import exceptions
from neutron.common.azconfig import azure_conf
from neutron.common import azutils
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

    @resource_registry.tracked_resources(router=router,
                                         floatingip=floating_ip)
    def __init__(self):
        super(AzureRouterPlugin, self).__init__()
        l3_db.subscribe()
        self._compute_client = None

        LOG.info("Azure Router plugin init with %s project, %s region" %
                 (azure_conf.tenant_id, azure_conf.region))

    @property
    def compute_client(self):
        if self._compute_client is None:
            args = (azure_conf.tenant_id, azure_conf.client_id, azure_conf.client_secret,
                    azure_conf.subscription_id)
            self.compute_client = azutils.get_compute_client(*args)
        return self._compute_client

    def get_plugin_type(self):
        return plugin_type

    def get_plugin_description(self):
        """returns string description of the plugin."""
        return ("Azure L3 Router Service Plugin for basic L3 forwarding"
                " between (L2) Neutron networks and access to external"
                " networks via a NAT gateway.")

    def create_floatingip(self, context, floatingip):
        raise NotImplementedError()

    def update_floatingip(self, context, id, floatingip):
        raise NotImplementedError()

    def delete_floatingip(self, context, id):
        raise NotImplementedError()

    def create_router(self, context, router):
        raise NotImplementedError()

    def delete_router(self, context, id):
        raise NotImplementedError()

    def update_router(self, context, id, router):
        raise NotImplementedError()

    def add_router_interface(self, context, router_id, interface_info):
        raise NotImplementedError()

    def remove_router_interface(self, context, router_id, interface_info):
        raise NotImplementedError()
