# Copyright 2016 Platform9 Systems Inc.(http://www.platform9.com)
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
        LOG.info("Innitialize GCE Mechanism Driver")
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
        """Allocate resources for a new network.

        :param context: NetworkContext instance describing the new
        network.

        Create a new network, allocating resources as necessary in the
        database. Called inside transaction context on session. Call
        cannot block.  Raising an exception will result in a rollback
        of the current transaction.
        """
        LOG.info("create_network_precommit {0}".format(context.__dict__))
        pass

    def create_network_postcommit(self, context):
        """Create a network.

        :param context: NetworkContext instance describing the new
        network.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Raising an exception will
        cause the deletion of the resource.
        """
        LOG.info("create_network_postcommit {0}".format(context.current))
        compute, project = self.gce_svc, self.gce_project
        name = self._gce_network_name(context)
        operation = gceutils.create_network(compute, project, name)
        gceutils.wait_for_operation(compute, project, operation)
        LOG.info('Created network on GCE %s' % name)

    def update_network_precommit(self, context):
        """Update resources of a network.

        :param context: NetworkContext instance describing the new
        state of the network, as well as the original state prior
        to the update_network call.

        Update values of a network, updating the associated resources
        in the database. Called inside transaction context on session.
        Raising an exception will result in rollback of the
        transaction.

        update_network_precommit is called for all changes to the
        network state. It is up to the mechanism driver to ignore
        state or state changes that it does not know or care about.
        """
        LOG.info("update_network_precommit {0}".format(context.__dict__))
        pass

    def update_network_postcommit(self, context):
        """Update a network.

        :param context: NetworkContext instance describing the new
        state of the network, as well as the original state prior
        to the update_network call.

        will block the entire process so care should be taken to not
        drastically affect performance. Raising an exception will
        cause the deletion of the resource.

        update_network_postcommit is called for all changes to the
        network state.  It is up to the mechanism driver to ignore
        state or state changes that it does not know or care about.
        """
        LOG.info("update_network_postcommit {0}".format(context.__dict__))
        pass

    def delete_network_precommit(self, context):
        """Delete resources for a network.

        :param context: NetworkContext instance describing the current
        state of the network, prior to the call to delete it.

        Delete network resources previously allocated by this
        mechanism driver for a network. Called inside transaction
        context on session. Runtime errors are not expected, but
        raising an exception will result in rollback of the
        transaction.
        """
        LOG.info("delete_network_precommit {0}".format(context.__dict__))
        pass

    def delete_network_postcommit(self, context):
        """Delete a network.

        :param context: NetworkContext instance describing the current
        state of the network, prior to the call to delete it.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Runtime errors are not
        expected, and will not prevent the resource from being
        deleted.
        """
        LOG.info("delete_network_postcommit {0}".format(context.current))
        compute, project = self.gce_svc, self.gce_project
        name = self._gce_network_name(context)
        operation = gceutils.delete_network(compute, project, name)
        gceutils.wait_for_operation(compute, project, operation)
        LOG.info('Deleted network on GCE %s' % name)

    def create_subnet_precommit(self, context):
        """Allocate resources for a new subnet.

        :param context: SubnetContext instance describing the new
        subnet.

        Create a new subnet, allocating resources as necessary in the
        database. Called inside transaction context on session. Call
        cannot block.  Raising an exception will result in a rollback
        of the current transaction.
        """
        LOG.info("create_subnet_precommit {0}".format(context.__dict__))
        pass

    def create_subnet_postcommit(self, context):
        """Create a subnet.

        :param context: SubnetContext instance describing the new
        subnet.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Raising an exception will
        cause the deletion of the resource.
        """
        LOG.info("create_subnet_postcommit {0}".format(context.current))
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
        """Update resources of a subnet.

        :param context: SubnetContext instance describing the new
        state of the subnet, as well as the original state prior
        to the update_subnet call.

        Update values of a subnet, updating the associated resources
        in the database. Called inside transaction context on session.
        Raising an exception will result in rollback of the
        transaction.

        update_subnet_precommit is called for all changes to the
        subnet state. It is up to the mechanism driver to ignore
        state or state changes that it does not know or care about.
        """
        LOG.info("update_subnet_precommit {0}".format(context.__dict__))
        pass

    def update_subnet_postcommit(self, context):
        """Update a subnet.

        :param context: SubnetContext instance describing the new
        state of the subnet, as well as the original state prior
        to the update_subnet call.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Raising an exception will
        cause the deletion of the resource.

        update_subnet_postcommit is called for all changes to the
        subnet state.  It is up to the mechanism driver to ignore
        state or state changes that it does not know or care about.
        """
        LOG.info("update_subnet_postcommit {0}".format(context.__dict__))
        pass

    def delete_subnet_precommit(self, context):
        """Delete resources for a subnet.

        :param context: SubnetContext instance describing the current
        state of the subnet, prior to the call to delete it.

        Delete subnet resources previously allocated by this
        mechanism driver for a subnet. Called inside transaction
        context on session. Runtime errors are not expected, but
        raising an exception will result in rollback of the
        transaction.
        """
        LOG.info("delete_subnet_precommit {0}".format(context.__dict__))
        pass

    def delete_subnet_postcommit(self, context):
        """Delete a subnet.

        :param context: SubnetContext instance describing the current
        state of the subnet, prior to the call to delete it.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Runtime errors are not
        expected, and will not prevent the resource from being
        deleted.
        """
        LOG.info("delete_subnet_postcommit {0}".format(context.current))
        compute, project, region = self.gce_svc, self.gce_project, self.gce_region
        cidr = context.current['cidr']
        if self.is_private_network(cidr):
            name = self._gce_subnet_name(context)
            operation = gceutils.delete_subnet(compute, project, region, name)
            gceutils.wait_for_operation(compute, project, operation)
            LOG.info("Deleted subnet %s in region %s on GCE" % (name, region))

    def bind_port(self, context):
        """Attempt to bind a port.

        :param context: PortContext instance describing the port

        This method is called outside any transaction to attempt to
        establish a port binding using this mechanism driver. Bindings
        may be created at each of multiple levels of a hierarchical
        network, and are established from the top level downward. At
        each level, the mechanism driver determines whether it can
        bind to any of the network segments in the
        context.segments_to_bind property, based on the value of the
        context.host property, any relevant port or network
        attributes, and its own knowledge of the network topology. At
        the top level, context.segments_to_bind contains the static
        segments of the port's network. At each lower level of
        binding, it contains static or dynamic segments supplied by
        the driver that bound at the level above. If the driver is
        able to complete the binding of the port to any segment in
        context.segments_to_bind, it must call context.set_binding
        with the binding details. If it can partially bind the port,
        it must call context.continue_binding with the network
        segments to be used to bind at the next lower level.

        If the binding results are committed after bind_port returns,
        they will be seen by all mechanism drivers as
        update_port_precommit and update_port_postcommit calls. But if
        some other thread or process concurrently binds or updates the
        port, these binding results will not be committed, and
        update_port_precommit and update_port_postcommit will not be
        called on the mechanism drivers with these results. Because
        binding results can be discarded rather than committed,
        drivers should avoid making persistent state changes in
        bind_port, or else must ensure that such state changes are
        eventually cleaned up.

        Implementing this method explicitly declares the mechanism
        driver as having the intention to bind ports. This is inspected
        by the QoS service to identify the available QoS rules you
        can use with ports.
        """
        LOG.info("bind_port {0}".format(context.__dict__))
        fixed_ip_dict = dict()
        if 'fixed_ips' in context.current:
            if len(context.current['fixed_ips']) > 0:
                fixed_ip_dict = context.current['fixed_ips'][0]
        segment_id = random.choice(context.segments_to_bind)[api.ID]
        context.set_binding(segment_id, "vip_type_a", fixed_ip_dict,
                            status='ACTIVE')
        return True
