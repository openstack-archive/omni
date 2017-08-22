"""
Copyright (c) 2017 Platform9 Systems Inc.
Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""

from nova import exception
from nova.compute import task_states
from nova.virt import driver
from nova.virt import hardware
from nova.virt.azure import utils as azutils
from nova.virt.azure import constants
from nova.virt.azure.config import azure_conf as drv_conf
from nova.virt.azure.config import nova_conf
from oslo_log import log as logging

import hashlib
import uuid

LOG = logging.getLogger(__name__)
_DRV_NODES = None

DIAGNOSTIC_KEYS_TO_FILTER = ['group', 'block_device_mapping']
OMNI_ID = constants.OMNI_ID


def set_nodes(nodes):
    """Sets Driver's node list.
    It has effect on the following methods:
        get_available_nodes()
        get_available_resource
        get_host_stats()

    To restore the change, call restore_nodes()
    """
    global _DRV_NODES
    _DRV_NODES = nodes


def restore_nodes():
    """Resets Azure Driver's node list modified by set_nodes().
    Usually called from tearDown().
    """
    global _DRV_NODES
    _DRV_NODES = [nova_conf.host]


class AzureDriver(driver.ComputeDriver):
    capabilities = {
        "has_imagecache": True,
        "supports_recreate": True,
    }

    def __init__(self, virtapi, read_only=False):
        super(AzureDriver, self).__init__(virtapi)
        self.name = 'Azure'
        self.version = '1.0'
        self.host_status_base = {
            'vcpus': drv_conf.max_vcpus,
            'memory_mb': drv_conf.max_memory_mb,
            'local_gb': drv_conf.max_disk_gb,
            'vcpus_used': 0,
            'memory_mb_used': 0,
            'local_gb_used': 0,
            'hypervisor_type': self.name,
            'hypervisor_version': self.version,
            'hypervisor_hostname': nova_conf.host,
            'cpu_info': {},
            'disk_available_least': drv_conf.max_disk_gb,
        }
        self._mounts = {}
        self._interfaces = {}
        self._uuid_to_omni_instance = {}
        # PF9 : Start
        self._pf9_stats = {}
        # PF9 : End

    def init_host(self, host):
        """Initialize anything that is necessary for the driver to function"""
        global _DRV_NODES
        if _DRV_NODES is None:
            set_nodes([nova_conf.host])
        args = (drv_conf.tenant_id, drv_conf.client_id, drv_conf.client_secret,
                drv_conf.subscription_id)

        self.compute_client = azutils.get_compute_client(*args)
        self.resource_client = azutils.get_resource_client(*args)
        self.network_client = azutils.get_network_client(*args)

        self.flavor_info = azutils.get_vm_sizes(self.compute_client,
                                                drv_conf.region)
        LOG.info("%s driver init with %s project, %s region" %
                 (self.name, drv_conf.tenant_id, drv_conf.region))

    def _get_uuid_from_omni_id(self, omni_id):
        m = hashlib.md5()
        m.update(omni_id)
        return str(uuid.UUID(bytes=m.digest(), version=4))

    def _get_omni_id_from_instance(self, instance):
        if OMNI_ID in instance.metadata and instance.metadata[OMNI_ID]:
            return instance.metadata[OMNI_ID]
        elif instance.uuid in self._uuid_to_omni_instance:
            return self._uuid_to_omni_instance[instance.uuid].name
        # if none of the conditions are met we cannot map OpenStack UUID to
        # Azure ID.
        raise exception.InstanceNotFound(
            'Instance %s not found' % instance.uuid)

    def list_instances(self):
        """
        Return the names of all the instances known to the virtualization
        layer, as a list.
        """
        # TODO: Catch exception
        instances = azutils.list_instances(self.compute_client,
                                           drv_conf.resource_group)

        self._uuid_to_omni_instance.clear()
        instance_names = []
        for instance in instances:
            openstack_id = None
            if instance.tags and 'openstack_id' in instance.tags:
                openstack_id = instance.tags['openstack_id']
            if openstack_id is None:
                openstack_id = self._get_uuid_from_omni_id(instance.name)
            self._uuid_to_omni_instance[openstack_id] = instance
            instance_names.append(instance.name)
        return instance_names

    def plug_vifs(self, instance, network_info):
        """Plug VIFs into networks."""
        raise NotImplementedError()

    def unplug_vifs(self, instance, network_info):
        """Unplug VIFs from networks."""
        raise NotImplementedError()

    def spawn(self,
              context,
              instance,
              image_meta,
              injected_files,
              admin_password,
              network_info=None,
              block_device_info=None):
        """Create a new instance/VM/domain on the virtualization platform.
        Once this successfully completes, the instance should be
        running (power_state.RUNNING). If this fails, any partial instance
        should be completely cleaned up, and the virtualization platform should
        be in the state that it was before this call began.

        :param context: security context <Not Yet Implemented>
        :param instance: nova.objects.instance.Instance
                         This function should use the data there to guide
                         the creation of the new instance.
        :param image_meta: image object returned by nova.image.glance that
                           defines the image from which to boot this instance
        :param injected_files: User files to inject into instance.
        :param admin_password: set in instance. <Not Yet Implemented>
        :param network_info:
           :py:meth:`~nova.network.manager.NetworkManager.get_instance_nw_info`
        :param block_device_info: Information about block devices to be
                                  attached to the instance.
        """
        raise NotImplementedError()

    def snapshot(self, context, instance, image_id, update_task_state):
        """Snapshot an image of the specified instance

        :param context: security context
        :param instance: nova.objects.instance.Instance
        :param image_id: Reference to a pre-created image holding the snapshot.

        """
        raise NotImplementedError()

    def reboot(self,
               context,
               instance,
               network_info,
               reboot_type,
               block_device_info=None,
               bad_volumes_callback=None):
        """Reboot the specified instance. After this is called successfully,
        the instance's state goes back to power_state.RUNNING. The
        virtualization platform should ensure that the reboot action has
        completed successfully even in cases in which the underlying domain/vm
        is paused or halted/stopped.

        :param instance: nova.objects.instance.Instance
        :param network_info:
           :py:meth:`~nova.network.manager.NetworkManager.get_instance_nw_info`
        :param reboot_type: Either a HARD or SOFT reboot
        :param block_device_info: Info pertaining to attached volumes
        :param bad_volumes_callback: Function to handle any bad volumes
            encountered
        """
        if reboot_type == 'SOFT':
            self._soft_reboot(context, instance, network_info,
                              block_device_info)
        elif reboot_type == 'HARD':
            self._hard_reboot(context, instance, network_info,
                              block_device_info)

    def _soft_reboot(self,
                     context,
                     instance,
                     network_info,
                     block_device_info=None):
        raise NotImplementedError()

    def _hard_reboot(self,
                     context,
                     instance,
                     network_info,
                     block_device_info=None):
        raise NotImplementedError()

    @staticmethod
    def get_host_ip_addr():
        """Retrieves the IP address of the host"""
        return nova_conf.my_ip

    def set_admin_password(self, instance, new_pass):
        """Set root password on specified instance"""
        raise NotImplementedError()

    def inject_file(self, instance, b64_path, b64_contents):
        raise NotImplementedError()

    def resume_state_on_host_boot(self,
                                  context,
                                  instance,
                                  network_info,
                                  block_device_info=None):
        raise NotImplementedError()

    def rescue(self, context, instance, network_info, image_meta,
               rescue_password):
        raise NotImplementedError()

    def unrescue(self, instance, network_info):
        raise NotImplementedError()

    def poll_rebooting_instances(self, timeout, instances):
        raise NotImplementedError()

    def migrate_disk_and_power_off(self,
                                   context,
                                   instance,
                                   dest,
                                   instance_type,
                                   network_info,
                                   block_device_info=None):
        raise NotImplementedError()

    def finish_revert_migration(self,
                                context,
                                instance,
                                network_info,
                                block_device_info=None,
                                power_on=True):
        raise NotImplementedError()

    def post_live_migration_at_destination(self,
                                           context,
                                           instance,
                                           network_info,
                                           block_migration=False,
                                           block_device_info=None):
        raise NotImplementedError()

    def power_off(self, instance, timeout=0, retry_interval=0):
        """Power off the specified instance.

        :param instance: nova.objects.instance.Instance
        :param timeout: time to wait for GuestOS to shutdown
        :param retry_interval: How often to signal guest while
                               waiting for it to shutdown
        """
        raise NotImplementedError()

    def power_on(self, context, instance, network_info, block_device_info):
        """Power on the specified instance."""
        raise NotImplementedError()

    def soft_delete(self, instance):
        """Deleting the specified instance"""
        raise NotImplementedError()

    def restore(self, instance):
        raise NotImplementedError()

    def pause(self, instance):
        """
        Azure doesn't support pause and cannot save system state and hence
        we've implemented the closest functionality which is to poweroff the
        instance.

        :param instance: nova.objects.instance.Instance
        """
        self.power_off(instance)

    def unpause(self, instance):
        """
        Since Azure doesn't support pause and cannot save system state, we
        had implemented the closest functionality which is to poweroff the
        instance. and powering on such an instance in this method.

        :param instance: nova.objects.instance.Instance
        """
        self.power_on(
            context=None,
            instance=instance,
            network_info=None,
            block_device_info=None)

    def suspend(self, context, instance):
        """
        Azure doesn't support suspend and cannot save system state and hence
        Azure doesn't support suspend and cannot save system state and hence
        we've implemented the closest functionality which is to poweroff the
        instance.

        :param instance: nova.objects.instance.Instance
        """
        LOG.info("Suspending instance %s" % instance.uuid)
        self.power_off(instance)

    def resume(self, context, instance, network_info, block_device_info=None):
        """
        Since Azure doesn't support resume and we cannot save system state,
        Since Azure doesn't support resume and we cannot save system state,
        we've implemented the closest functionality which is to power on the
        instance.

        :param instance: nova.objects.instance.Instance
        """
        LOG.info("Resuming instance %s" % instance.uuid)
        self.power_on(context, instance, network_info, block_device_info)

    def destroy(self,
                context,
                instance,
                network_info,
                block_device_info=None,
                destroy_disks=True,
                migrate_data=None):
        """Destroy the specified instance from the Hypervisor.
        If the instance is not found (for example if networking failed), this
        function should still succeed.  It's probably a good idea to log a
        warning in that case.

        :param context: security context
        :param instance: Instance object as returned by DB layer.
        :param network_info:
           :py:meth:`~nova.network.manager.NetworkManager.get_instance_nw_info`
        :param block_device_info: Information about block devices that should
                                  be detached from the instance.
        :param destroy_disks: Indicates if disks should be destroyed
        :param migrate_data: implementation specific params
        """
        raise NotImplementedError()

    def attach_volume(self,
                      context,
                      connection_info,
                      instance,
                      mountpoint,
                      disk_bus=None,
                      device_type=None,
                      encryption=None):
        """Attach the disk to the instance at mountpoint using info."""
        raise NotImplementedError()

    def detach_volume(self,
                      connection_info,
                      instance,
                      mountpoint,
                      encryption=None):
        """Detach the disk attached to the instance."""
        raise NotImplementedError()

    def swap_volume(self, old_connection_info, new_connection_info, instance,
                    mountpoint, resize_to):
        """Replace the disk attached to the instance."""
        raise NotImplementedError()

    def attach_interface(self, instance, image_meta, vif):
        raise NotImplementedError()

    def detach_interface(self, instance, vif):
        raise NotImplementedError()

    def get_info(self, instance):
        """Get the current status of an instance, by name (not ID!)

        :param instance: nova.objects.instance.Instance object
        Returns a dict containing:
        :state:           the running state, one of the power_state codes
        :max_mem:         (int) the maximum memory in KBytes allowed
        :mem:             (int) the memory in KBytes used by the domain
        :num_cpu:         (int) the number of virtual CPUs for the domain
        :cpu_time:        (int) the CPU time used in nanoseconds
        """
        raise NotImplementedError()

    def allow_key(self, key):
        if key in DIAGNOSTIC_KEYS_TO_FILTER:
            return False
        return True

    def get_diagnostics(self, instance):
        """Return data about VM diagnostics."""
        # Fake diagnostics
        return {
            'cpu0_time': 17300000000,
            'memory': 524288,
            'vda_errors': -1,
            'vda_read': 262144,
            'vda_read_req': 112,
            'vda_write': 5778432,
            'vda_write_req': 488,
            'vnet1_rx': 2070139,
            'vnet1_rx_drop': 0,
            'vnet1_rx_errors': 0,
            'vnet1_rx_packets': 26701,
            'vnet1_tx': 140208,
            'vnet1_tx_drop': 0,
            'vnet1_tx_errors': 0,
            'vnet1_tx_packets': 662,
        }

    def get_all_bw_counters(self, instances):
        """Return bandwidth usage counters for each interface on each
           running VM.
        """

        bw = []
        return bw

    def get_all_volume_usage(self, context, compute_host_bdms):
        """Return usage info for volumes attached to vms on a given host."""
        volusage = []
        return volusage

    def block_stats(self, instance_name, disk_id):
        return [0L, 0L, 0L, 0L, None]

    def interface_stats(self, instance_name, iface_id):
        return [0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L]

    def get_vnc_console(self, context, instance):
        raise NotImplementedError()

    def get_spice_console(self, instance):
        """Simple Protocol for Independent Computing Environments"""
        raise NotImplementedError()

    def get_console_pool_info(self, console_type):
        raise NotImplementedError()

    def refresh_provider_fw_rules(self):
        raise NotImplementedError()

    def get_available_resource(self, nodename):
        """Retrieve resource information. Updates compute manager resource info
        on ComputeNode table. This method is called when nova-compute launches
        and as part of a periodic task that records results in the DB. Without
        real hypervisor, pretend we have lots of disk and ram.

        :param nodename: node which the caller want to get resources from
        a driver that manages only one node can safely ignore this
        :returns: Dictionary describing resources
        """

        global _DRV_NODES
        if nodename not in _DRV_NODES:
            return {}

        dic = {
            'vcpus': drv_conf.max_vcpus,
            'memory_mb': drv_conf.max_memory_mb,
            'local_gb': drv_conf.max_disk_gb,
            'vcpus_used': 0,
            'memory_mb_used': 0,
            'local_gb_used': 0,
            'hypervisor_type': self.name,
            'hypervisor_version': '1',
            'hypervisor_hostname': nodename,
            'disk_available_least': 0,
            'cpu_info': '?',
            'numa_topology': None
        }

        supported_tuple = ('IA64', 'kvm', 'hvm')
        dic["supported_instances"] = [supported_tuple]
        return dic

    def ensure_filtering_rules_for_instance(self, instance_ref, network_info):
        return

    def get_instance_disk_info(self, instance_name):
        return

    def live_migration(self,
                       context,
                       instance_ref,
                       dest,
                       post_method,
                       recover_method,
                       block_migration=False,
                       migrate_data=None):
        post_method(context, instance_ref, dest, block_migration, migrate_data)
        return

    def check_can_live_migrate_destination_cleanup(self, ctxt,
                                                   dest_check_data):
        return

    def check_can_live_migrate_destination(self,
                                           ctxt,
                                           instance_ref,
                                           src_compute_info,
                                           dst_compute_info,
                                           block_migration=False,
                                           disk_over_commit=False):
        return {}

    def check_can_live_migrate_source(self, ctxt, instance_ref,
                                      dest_check_data):
        return

    def finish_migration(self,
                         context,
                         migration,
                         instance,
                         disk_info,
                         network_info,
                         image_meta,
                         resize_instance,
                         block_device_info=None,
                         power_on=True):
        """Completes a resize

        :param migration: the migrate/resize information
        :param instance: nova.objects.instance.Instance being migrated/resized
        :param power_on: is True  the instance should be powered on
        """
        raise NotImplementedError()

    def confirm_migration(self, migration, instance, network_info):
        """Confirms a resize, destroying the source VM.

        :param instance: nova.objects.instance.Instance
        """
        raise NotImplementedError()

    def pre_live_migration(self,
                           context,
                           instance_ref,
                           block_device_info,
                           network_info,
                           disk,
                           migrate_data=None):
        return

    def unfilter_instance(self, instance_ref, network_info):
        return

    def get_host_stats(self, refresh=False):
        """Return Azure Host Status of name, ram, disk, network."""
        global _DRV_NODES
        stats = []
        for nodename in _DRV_NODES:
            host_status = self.host_status_base.copy()
            host_status['hypervisor_hostname'] = nodename
            host_status['host_hostname'] = nodename
            host_status['host_name_label'] = nodename
            host_status['hypervisor_type'] = self.name
            host_status['vcpus'] = drv_conf.max_vcpus
            host_status['memory_mb'] = drv_conf.max_memory_mb
            host_status['local_gb'] = drv_conf.max_disk_gb
            stats.append(host_status)
        if len(stats) == 0:
            raise exception.NovaException("Azure Driver has no node")
        elif len(stats) == 1:
            return stats[0]
        else:
            return stats

    def host_power_action(self, host, action):
        """Reboots, shuts down or powers up the host."""
        return action

    def host_maintenance_mode(self, host, mode):
        """Start/Stop host maintenance window. On start, it triggers
        guest VMs evacuation.
        """

        if not mode:
            return 'off_maintenance'
        return 'on_maintenance'

    def set_host_enabled(self, host, enabled):
        """Sets the specified host's ability to accept new instances."""
        if enabled:
            return 'enabled'
        return 'disabled'

    def get_disk_available_least(self):
        raise NotImplementedError()

    def add_to_aggregate(self, context, aggregate, host, **kwargs):
        raise NotImplementedError()

    def remove_from_aggregate(self, context, aggregate, host, **kwargs):
        raise NotImplementedError()

    def get_volume_connector(self, instance):
        return {
            'ip': '127.0.0.1',
            'initiator': self.name,
            'host': '%shost' % self.name
        }

    def get_available_nodes(self, refresh=False):
        global _DRV_NODES
        return _DRV_NODES

    def instance_on_disk(self, instance):
        return False

    def list_instance_uuids(self, node=None, template_uuids=None, force=False):
        self.list_instances()
        return self._uuid_to_omni_instance.keys()

    # PF9 : Start
    def get_instance_info(self, instance_uuid):
        retval = {}
        return retval

    def _update_stats_pf9(self, resource_type):
        """Retrieve physical resource utilization
        """
        if resource_type not in self._pf9_stats:
            self._pf9_stats = {}
        data = 0
        self._pf9_stats[resource_type] = data
        return {resource_type: data}

    def _get_host_stats_pf9(self, res_types, refresh=False):
        """Return the current physical resource consumption
        """
        if refresh or not self._pf9_stats:
            self._update_stats_pf9(res_types)
        return self._pf9_stats

    def get_host_stats_pf9(self, res_types, refresh=False, nodename=None):
        """Return currently known physical resource consumption
        If 'refresh' is True, run update the stats first.
        :param res_types: An array of resources to be queried
        """
        resource_stats = dict()
        for resource_type in res_types:
            LOG.info("Looking for resource: %s" % resource_type)
            resource_dict = self._get_host_stats_pf9(
                resource_type, refresh=refresh)
            resource_stats.update(resource_dict)
        return resource_stats

    def get_all_networks_pf9(self, node):
        pass

    def get_all_ip_mapping_pf9(self, needed_uuids=None):
        return {}

    # PF9 : End
