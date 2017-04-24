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

import ipaddr
from neutron.common import gceconf, gceutils
from neutron.plugins.ml2 import driver_api as api
from oslo_log import log

LOG = log.getLogger(__name__)


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
        LOG.info("GCE Mechanism driver init with %s project, %s region" %
                 (self.gce_project, self.gce_region))

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
        LOG.debug("create_network_postcommit {0}".format(context.current))
        compute, project = self.gce_svc, self.gce_project
        name = self._gce_network_name(context)
        operation = gceutils.create_network(compute, project, name)
        gceutils.wait_for_operation(compute, project, operation)
        LOG.info('Created network on GCE %s' % name)

    def update_network_precommit(self, context):
        pass

    def update_network_postcommit(self, context):
        pass

    def delete_network_precommit(self, context):
        pass

    def delete_network_postcommit(self, context):
        LOG.debug("delete_network_postcommit {0}".format(context.current))
        compute, project = self.gce_svc, self.gce_project
        name = self._gce_network_name(context)
        operation = gceutils.delete_network(compute, project, name)
        gceutils.wait_for_operation(compute, project, operation)
        LOG.info('Deleted network on GCE %s' % name)

    def create_subnet_precommit(self, context):
        pass

    def create_subnet_postcommit(self, context):
        LOG.debug("create_subnet_postcommit {0}".format(context.current))
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
            LOG.info("Created subnet %s in region %s on GCE" % (name, region))

    def update_subnet_precommit(self, context):
        pass

    def update_subnet_postcommit(self, context):
        pass

    def delete_subnet_precommit(self, context):
        pass

    def delete_subnet_postcommit(self, context):
        LOG.debug("delete_subnet_postcommit {0}".format(context.current))
        compute, project, region = self.gce_svc, self.gce_project, self.gce_region
        cidr = context.current['cidr']
        if self.is_private_network(cidr):
            name = self._gce_subnet_name(context)
            operation = gceutils.delete_subnet(compute, project, region, name)
            gceutils.wait_for_operation(compute, project, operation)
            LOG.info("Deleted subnet %s in region %s on GCE" % (name, region))

    def bind_port(self, context):
        LOG.debug("bind_port {0}".format(context.current))
        fixed_ip_dict = dict()
        if 'fixed_ips' in context.current:
            if len(context.current['fixed_ips']) > 0:
                fixed_ip_dict = context.current['fixed_ips'][0]
        segment_id = random.choice(context.segments_to_bind)[api.ID]
        context.set_binding(segment_id, "vip_type_a", fixed_ip_dict,
                            status='ACTIVE')
        return True
