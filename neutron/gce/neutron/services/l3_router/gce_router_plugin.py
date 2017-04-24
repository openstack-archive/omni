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

from neutron_lib import constants as n_const
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
from oslo_log import log as logging
from neutron.common import exceptions
from neutron.db import securitygroups_db

from neutron.common import gceconf
from neutron.common import gceutils

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
        "l3-ha", "security-group"
    ]

    @resource_registry.tracked_resources(
        router=l3_db.Router,
        floatingip=l3_db.FloatingIP,
        security_group=securitygroups_db.SecurityGroup)
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

    def create_floatingip(self, context, floatingip):
        LOG.info('create floating ip %s' % (floatingip, ))
        compute, project, region = self.gce_svc, self.gce_project, self.gce_region
        ip_name = 'instanceip'

        try:
            operation = gceutils.create_static_ip(compute, project, region,
                                                  ip_name)
            gceutils.wait_for_operation(compute, project, operation)

            address_info = gceutils.get_static_ip(compute, project, region,
                                                  ip_name)

            public_ip_allocated = address_info['address']

            LOG.info("Created static IP %s" % public_ip_allocated)
            if 'floatingip' in floatingip:
                floatingip['floatingip'][
                    'floating_ip_address'] = public_ip_allocated

            if 'port_id' in floatingip['floatingip'] and floatingip['floatingip']['port_id'] is not None:
                # Associate to a Port
                port_id = floatingip['floatingip']['port_id']
                self._associate_floatingip_to_port(
                    context, public_ip_allocated, port_id)
        except Exception as e:
            LOG.error("Error in Creation/Allocating EIP")
            if public_ip_allocated:
                LOG.error("Deleting Elastic IP: %s" % public_ip_allocated)
                gceutils.delete_static_ip(compute, project, region, ip_name)
            raise e

        try:
            res = super(GceRouterPlugin, self).create_floatingip(
                context,
                floatingip,
                initial_status=n_const.FLOATINGIP_STATUS_DOWN)
        except Exception as e:
            LOG.error(
                "Error when adding floating ip in openstack. Deleting Elastic IP: %s"
                % public_ip_allocated)
            gceutils.delete_static_ip(compute, project, region, ip_name)
            raise e
        return res

    def _associate_floatingip_to_port(self, context, floating_ip_address,
                                      port_id):
        pass
        """
        port = self._core_plugin.get_port(context, port_id)
        gce_id = None
        fixed_ip_address = None
        # TODO: Assuming that there is only one fixed IP
        if len(port['fixed_ips']) > 0:
            fixed_ip = port['fixed_ips'][0]
            if 'ip_address' in fixed_ip:
                fixed_ip_address = fixed_ip['ip_address']
                search_opts = {
                    'ip': fixed_ip_address,
                    'tenant_id': context.tenant_id
                }
                server_list = self.aws_utils.get_nova_client().servers.list(
                    search_opts=search_opts)
                if len(server_list) > 0:
                    server = server_list[0]
                    if 'ec2_id' in server.metadata:
                        ec2_id = server.metadata['ec2_id']
        if floating_ip_address is not None and ec2_id is not None:
            self.aws_utils.associate_elastic_ip_to_ec2_instance(
                floating_ip_address, ec2_id)
            LOG.info("EC2 ID found for IP %s : %s" % (fixed_ip_address,
                                                      ec2_id))
        else:
            LOG.warning("EC2 ID not found to associate the floating IP")
            raise exceptions.AwsException(
                error_code="No Server Found",
                message="No server found with the Required IP")
        """

    def update_floatingip(self, context, id, floatingip):
        floating_ip_dict = super(GceRouterPlugin, self).get_floatingip(
            context, id)
        LOG.info(' floating ip %s dict %s' % (floatingip, floating_ip_dict))
        """
        if 'floatingip' in floatingip and 'port_id' in floatingip['floatingip']:
            port_id = floatingip['floatingip']['port_id']
            if port_id is not None:
                # Associate Floating IP
                LOG.info("Associating elastic IP %s with port %s" %
                         (floating_ip_dict['floating_ip_address'], port_id))
                self._associate_floatingip_to_port(
                    context, floating_ip_dict['floating_ip_address'], port_id)
            else:
                try:
                    # Port Disassociate
                    self.aws_utils.disassociate_elastic_ip_from_ec2_instance(
                        floating_ip_dict['floating_ip_address'])
                except exceptions.AwsException as e:
                    if 'Association ID not found' in e.msg:
                        LOG.warn(
                            "Association for Elastic IP not found. Probable out of band change on EC2."
                        )
                    elif 'InvalidAddress.NotFound' in e.msg:
                        LOG.warn(
                            "Elastic IP cannot be found in EC2. Probably removed out of band on EC2."
                        )
                    else:
                        raise e
        """
        return super(GceRouterPlugin, self).update_floatingip(
            context, id, floatingip)

    def delete_floatingip(self, context, id):
        floating_ip = super(GceRouterPlugin, self).get_floatingip(context, id)
        LOG.info("delete floatingip %s" % floating_ip)
        """
        floating_ip_address = floating_ip['floating_ip_address']
        LOG.info("Deleting elastic IP %s" % floating_ip_address)
        try:
            self.aws_utils.delete_elastic_ip(floating_ip_address)
        except exceptions.AwsException as e:
            if 'InvalidAddress.NotFound' in e.msg:
                LOG.warn("Elastic IP not found on AWS. Cleaning up neutron db")
            else:
                raise e
        """
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
        LOG.info("Adding interface %s to router %s" % (interface_info,
                                                       router_id))
        return super(GceRouterPlugin, self).add_router_interface(
            context, router_id, interface_info)

    def remove_router_interface(self, context, router_id, interface_info):
        LOG.info("Deleting interface %s from router %s" % (interface_info,
                                                           router_id))
        return super(GceRouterPlugin, self).remove_router_interface(
            context, router_id, interface_info)
