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

import neutron_lib
from neutron_lib import constants as const
from neutron_lib.exceptions import NeutronException

from distutils.version import LooseVersion
from neutron.common.aws_utils import AwsException
from neutron.common.aws_utils import AwsUtils
from neutron.db import common_db_mixin
from neutron.db import extraroute_db
from neutron.db import l3_db
from neutron.db import l3_dvrscheduler_db
from neutron.db import l3_gwmode_db
from neutron.db import l3_hamode_db
from neutron.db import l3_hascheduler_db
from neutron.db import omni_resources
from neutron.plugins.common import constants
from neutron.quota import resource_registry
from neutron.services import service_base
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


class RouterIdInvalidException(NeutronException):
    message = "Omni mapping for router %(router_id)s could not be found"


class AwsRouterPlugin(
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
        "l3-ha", "security-group"
    ]

    @resource_registry.tracked_resources(
        router=router, floatingip=floating_ip)
    def __init__(self):
        self.aws_utils = AwsUtils()
        super(AwsRouterPlugin, self).__init__()

    def get_plugin_type(self):
        return plugin_type

    def get_plugin_description(self):
        """returns string description of the plugin."""
        return ("AWS L3 Router Service Plugin for basic L3 forwarding"
                " between (L2) Neutron networks and access to external"
                " networks via a NAT gateway.")

    # FLOATING IP FEATURES

    def create_floatingip(self, context, floatingip):
        public_ip_allocated = floatingip['floatingip']['floating_ip_address']
        if public_ip_allocated:
            LOG.info("Discovered floating ip %s", public_ip_allocated)
        else:
            public_ip_allocated = None
            try:
                response = self.aws_utils.allocate_elastic_ip(context)
                public_ip_allocated = response['PublicIp']
                LOG.info("Created elastic IP %s" % public_ip_allocated)
                if 'floatingip' in floatingip:
                    floatingip['floatingip'][
                        'floating_ip_address'] = public_ip_allocated

                if ('port_id' in floatingip['floatingip'] and
                        floatingip['floatingip']['port_id'] is not None):
                    # Associate to a Port
                    port_id = floatingip['floatingip']['port_id']
                    self._associate_floatingip_to_port(
                        context, public_ip_allocated, port_id)
            except Exception as e:
                LOG.error("Error in Creation/Allocating EIP")
                if public_ip_allocated:
                    LOG.error("Deleting Elastic IP: %s" % public_ip_allocated)
                    self.aws_utils.delete_elastic_ip(public_ip_allocated,
                                                     context)
                raise e

        try:
            res = super(AwsRouterPlugin, self).create_floatingip(
                context, floatingip,
                initial_status=const.FLOATINGIP_STATUS_DOWN)
        except Exception as e:
            LOG.error("Error when adding floating ip in openstack. "
                      "Deleting Elastic IP: %s" % public_ip_allocated)
            raise e
        return res

    def _associate_floatingip_to_port(self, context, floating_ip_address,
                                      port_id):
        port = self._core_plugin.get_port(context, port_id)
        ec2_id = None
        fixed_ip_address = None
        # TODO(fixed_ip): Assuming that there is only one fixed IP
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
                floating_ip_address, ec2_id, context=context)
            LOG.info("EC2 ID found for IP %s : %s" % (fixed_ip_address,
                                                      ec2_id))
        else:
            LOG.warning("EC2 ID not found to associate the floating IP")
            raise AwsException(
                error_code="No Server Found",
                message="No server found with the Required IP")

    def update_floatingip(self, context, fip_id, floatingip):
        floating_ip_dict = super(AwsRouterPlugin, self).get_floatingip(
            context, fip_id)
        if ('floatingip' in floatingip and
                'port_id' in floatingip['floatingip']):
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
                        floating_ip_dict['floating_ip_address'], context)
                except AwsException as e:
                    if 'Association ID not found' in e.msg:
                        # Since its already disassociated on EC2, we continue
                        # and remove the association here.
                        LOG.warn("Association for Elastic IP not found. "
                                 "Probable out of band change on EC2.")
                    elif 'InvalidAddress.NotFound' in e.msg:
                        LOG.warn("Elastic IP cannot be found in EC2. Probably "
                                 "removed out of band on EC2.")
                    else:
                        raise e
        return super(AwsRouterPlugin, self).update_floatingip(
            context, fip_id, floatingip)

    def delete_floatingip(self, context, fip_id):
        floating_ip = super(AwsRouterPlugin, self).get_floatingip(
            context, fip_id)
        floating_ip_address = floating_ip['floating_ip_address']
        project_id = floating_ip['project_id']
        LOG.info("Deleting elastic IP %s" % floating_ip_address)
        try:
            self.aws_utils.delete_elastic_ip(floating_ip_address, context,
                                             project_id=project_id)
        except AwsException as e:
            if 'InvalidAddress.NotFound' in e.msg:
                LOG.warn("Elastic IP not found on AWS. Cleaning up neutron db")
            else:
                raise e
        return super(AwsRouterPlugin, self).delete_floatingip(context, fip_id)

    # ROUTERS

    def create_router(self, context, router):
        try:
            router_name = router['router']['name']
            ret_obj = super(AwsRouterPlugin, self).create_router(
                context, router)
            if router_name and router_name.startswith('igw-'):
                omni_resources.add_mapping(ret_obj['id'], router_name)
                LOG.info("Created discovered AWS router %s", router_name)
                return ret_obj

            internet_gw_res = self.aws_utils.create_internet_gateway_resource(
                context)
            tags = [{
                'Key': 'Name',
                'Value': router_name
            }, {
                'Key': 'openstack_router_id',
                'Value': ret_obj['id']
            }]
            self.aws_utils.create_resource_tags(internet_gw_res, tags)
            omni_resources.add_mapping(ret_obj['id'],
                                       internet_gw_res.internet_gateway_id)
            LOG.info("Created AWS router %s with openstack id %s" %
                     (router_name, ret_obj['id']))
            return ret_obj
        except Exception as e:
            LOG.error("Error while creating router %s" % e)
            raise e

    def delete_router(self, context, router_id):
        LOG.info("Deleting router %s" % router_id)
        if omni_resources.get_omni_resource(router_id) is None:
            raise RouterIdInvalidException(router_id=router_id)

        try:
            router_obj = self._get_router(context, router_id)
            if omni_resources.get_omni_resource(router_id) is None:
                raise AwsException(
                    "Router deletion failed, no AWS mapping found for %s" %
                    (router_id,))
            project_id = router_obj['project_id']
            router_name = router_obj['name']
            try:
                if router_name and router_name.startswith('igw-'):
                    self.aws_utils.detach_internet_gateway(
                        router_name, context, project_id=project_id)
                    self.aws_utils.delete_internet_gateway(
                        router_name, context, project_id=project_id)
                else:
                    self.aws_utils.detach_internet_gateway_by_router_id(
                        router_id, context, project_id=project_id)
                    self.aws_utils.delete_internet_gateway_by_router_id(
                        router_id, context, project_id=project_id)
            except AwsException as e:
                if 'InvalidInternetGatewayID.NotFound' in e.msg:
                    LOG.warn(e.msg)
                else:
                    raise e
            omni_resources.delete_mapping(router_id)
        except Exception as e:
            LOG.error("Error in Deleting Router: %s " % e)
            raise e
        return super(AwsRouterPlugin, self).delete_router(context, router_id)

    def update_router(self, context, router_id, router):
        # get internet gateway resource by openstack router id and update the
        # tags
        try:
            router_obj = self._get_router(context, router_id)
            router_name = router_obj['name']
            if router_name and router_name.startswith('igw-'):
                return super(AwsRouterPlugin, self).update_router(
                    context, router_id, router)

            if 'router' in router and 'name' in router['router']:
                router_name = router['router']['name']
                tags_list = [{
                    'Key': 'Name',
                    'Value': router_name
                }, {
                    'Key': 'openstack_router_id',
                    'Value': router_id
                }]
                LOG.info("Updated router %s" % router_id)
                self.aws_utils.create_tags_internet_gw_from_router_id(
                    router_id, tags_list, context)
        except Exception as e:
            LOG.error("Error in Updating Router: %s " % e)
            raise e
        return super(AwsRouterPlugin, self).update_router(
            context, router_id, router)

# ROUTER INTERFACE

    def add_router_interface(self, context, router_id, interface_info):
        subnet_id = interface_info['subnet_id']
        subnet_obj = self._core_plugin.get_subnet(context, subnet_id)
        router_obj = self._get_router(context, router_id)
        router_name = router_obj['name']
        if router_name and router_name.startswith('igw-'):
            LOG.info("Adding subnet %s to router %s", subnet_id, router_name)
            return super(AwsRouterPlugin, self).add_router_interface(
                context, router_id, interface_info)

        LOG.info("Adding subnet %s to router %s" % (subnet_id, router_id))
        neutron_network_id = subnet_obj['network_id']
        try:
            # Get Internet Gateway ID
            ig_id = self.aws_utils.get_internet_gw_from_router_id(
                router_id, context)
            # Get VPC ID
            vpc_id = self.aws_utils.get_vpc_from_neutron_network_id(
                neutron_network_id, context)
            self.aws_utils.attach_internet_gateway(ig_id, vpc_id, context)
            # Search for a Route table tagged with Router-id
            route_tables = self.aws_utils.get_route_table_by_router_id(
                router_id, context)
            if len(route_tables) == 0:
                # If not tagged, Fetch all the Route Tables Select one and tag
                # it
                route_tables = self.aws_utils.describe_route_tables_by_vpc_id(
                    vpc_id, context)
                if len(route_tables) > 0:
                    route_table = route_tables[0]
                    route_table_res = self.aws_utils._get_ec2_resource(
                        context).RouteTable(route_table['RouteTableId'])
                    route_table_res.create_tags(Tags=[{
                        'Key':
                        'openstack_router_id',
                        'Value':
                        router_id
                    }])
            if len(route_tables) > 0:
                route_table = route_tables[0]
                self.aws_utils.create_default_route_to_ig(
                    route_table['RouteTableId'], ig_id, context=context,
                    ignore_errors=True)
        except Exception as e:
            LOG.error("Error in Creating Interface: %s " % e)
            raise e
        return super(AwsRouterPlugin, self).add_router_interface(
            context, router_id, interface_info)

    def remove_router_interface(self, context, router_id, interface_info):
        if 'port_id' in interface_info:
            interface_id = interface_info['port_id']
            deleting_by = "port_id"
        elif 'subnet_id' in interface_info:
            interface_id = interface_info['subnet_id']
            deleting_by = "subnet_id"
        LOG.info("Deleting interface by {0} {1} from router {2}".format(
            deleting_by, interface_id, router_id))
        router_obj = self._get_router(context, router_id)
        project_id = router_obj['project_id']
        try:
            self.aws_utils.detach_internet_gateway_by_router_id(
                router_id, context, project_id=project_id)
        except AwsException as e:
            if 'InvalidInternetGatewayID.NotFound' in e.msg:
                LOG.warn(e.msg)
            else:
                raise e
        route_tables = self.aws_utils.get_route_table_by_router_id(
            router_id, context, project_id=project_id)
        if route_tables:
            route_table_id = route_tables[0]['RouteTableId']
            self.aws_utils.delete_default_route_to_ig(route_table_id, context,
                                                      project_id=project_id)
        return super(AwsRouterPlugin, self).remove_router_interface(
            context, router_id, interface_info)
