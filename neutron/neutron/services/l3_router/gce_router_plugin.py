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

from oslo_log import log as logging

from neutron.common import exceptions
from neutron.common import gceconf
from neutron.common import gceutils
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

LOG = logging.getLogger(__name__)


class GceRouterPlugin(
        service_base.ServicePluginBase, common_db_mixin.CommonDbMixin,
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

    @resource_registry.tracked_resources(router=l3_db.Router,
                                         floatingip=l3_db.FloatingIP)
    def __init__(self):
        super(GceRouterPlugin, self).__init__()
        l3_db.subscribe()
        self.gce_zone = gceconf.zone
        self.gce_region = gceconf.region
        self.gce_project = gceconf.project_id
        self.gce_svc_key = gceconf.service_key_path
        self.gce_svc = gceutils.get_gce_service(self.gce_svc_key)
        LOG.info("GCE Router plugin init with %s project, %s region" %
                 (self.gce_project, self.gce_region))

    def get_plugin_type(self):
        return constants.L3_ROUTER_NAT

    def get_plugin_description(self):
        """returns string description of the plugin."""
        return ("GCE L3 Router Service Plugin for basic L3 forwarding"
                " between (L2) Neutron networks and access to external"
                " networks via a NAT gateway.")

    def _cleanup_floatingip(self, compute, project, region, floatingip):
        gceutils.release_floatingip(compute, project, region, floatingip)
        gceutils.delete_floatingip(compute, project, region, floatingip)
        LOG.info('Released GCE static IP %s' % floatingip)

    def create_floatingip(self, context, floatingip):
        compute, project, region = self.gce_svc, self.gce_project, self.gce_region
        public_ip_allocated = None

        try:
            public_ip_allocated = gceutils.allocate_floatingip(
                compute, project, region)
            LOG.info("Created GCE static IP %s" % public_ip_allocated)

            floatingip_dict = floatingip['floatingip']

            floatingip_dict['floating_ip_address'] = public_ip_allocated

            if floatingip_dict.get('port_id'):
                port_id = floatingip_dict['port_id']
                self._associate_floatingip_to_port(
                    context, public_ip_allocated, port_id)
        except Exception as e:
            LOG.exception("Error in Creation/Allocating floating IP")
            if public_ip_allocated:
                self._cleanup_floatingip(compute, project, region,
                                         public_ip_allocated)
            raise e

        try:
            res = super(GceRouterPlugin, self).create_floatingip(
                context, floatingip,
                initial_status=n_const.FLOATINGIP_STATUS_DOWN)
        except Exception as e:
            LOG.exception("Error in adding floating IP")
            if public_ip_allocated:
                self._cleanup_floatingip(compute, project, region,
                                         public_ip_allocated)
            raise e
        return res

    def _associate_floatingip_to_port(self, context, floating_ip_address,
                                      port_id):
        compute, project, zone = self.gce_svc, self.gce_project, self.gce_zone
        port = self._core_plugin.get_port(context, port_id)
        fixed_ip_address = None
        if len(port['fixed_ips']) > 0:
            fixed_ip = port['fixed_ips'][0]
            if 'ip_address' in fixed_ip:
                fixed_ip_address = fixed_ip['ip_address']

        if fixed_ip_address:
            LOG.info('Found fixed ip %s for port %s' %
                     (fixed_ip_address, port_id))
            gceutils.assign_floatingip(compute, project, zone,
                                       fixed_ip_address, floating_ip_address)
        else:
            raise exceptions.FloatingIpSetupException(
                'Unable to find fixed ip for port %s' % port_id)

    def update_floatingip(self, context, id, floatingip):
        floatingip_dict = floatingip['floatingip']

        orig_floatingip = super(GceRouterPlugin, self).get_floatingip(
            context, id)
        public_ip_allocated = orig_floatingip['floating_ip_address']
        port_id = floatingip_dict['port_id']
        compute, project, region = self.gce_svc, self.gce_project, self.gce_region
        gceutils.release_floatingip(compute, project, region,
                                    public_ip_allocated)
        if port_id:
            self._associate_floatingip_to_port(context, public_ip_allocated,
                                               port_id)
        return super(GceRouterPlugin, self).update_floatingip(
            context, id, floatingip)

    def delete_floatingip(self, context, id):
        floating_ip = super(GceRouterPlugin, self).get_floatingip(context, id)
        public_ip_allocated = floating_ip['floating_ip_address']
        compute, project, region = self.gce_svc, self.gce_project, self.gce_region
        self._cleanup_floatingip(compute, project, region, public_ip_allocated)
        return super(GceRouterPlugin, self).delete_floatingip(context, id)

    def create_router(self, context, router):
        LOG.info("Creating router %s" % router['router']['name'])
        return super(GceRouterPlugin, self).create_router(context, router)

    def delete_router(self, context, id):
        LOG.info("Deleting router %s" % id)
        return super(GceRouterPlugin, self).delete_router(context, id)

    def update_router(self, context, id, router):
        LOG.info("Updating router %s" % id)
        return super(GceRouterPlugin, self).update_router(context, id, router)

    def add_router_interface(self, context, router_id, interface_info):
        LOG.info("Adding interface %s to router %s" %
                 (interface_info, router_id))
        return super(GceRouterPlugin, self).add_router_interface(
            context, router_id, interface_info)

    def remove_router_interface(self, context, router_id, interface_info):
        LOG.info("Deleting interface %s from router %s" %
                 (interface_info, router_id))
        return super(GceRouterPlugin, self).remove_router_interface(
            context, router_id, interface_info)
