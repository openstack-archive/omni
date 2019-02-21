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
from oslo_log import log as logging

from azure.mgmt.compute.models import VirtualMachineSize
from nova.virt.azure.config import azure_conf as drv_conf
from nova.virt.azure.config import nova_conf
from nova.virt.azure import utils

LOG = logging.getLogger(__name__)


class PF9NovaExtension(object):
    def __init__(self, drv_inst):
        self._pf9_stats = {}
        self.driver = drv_inst
        self._set_pf9_flavor()
        LOG.info("Init pf9 Nova extension")

    def _set_pf9_flavor(self):
        pf9_flavor = nova_conf.PF9.pf9_flavor
        self.driver.flavor_info[pf9_flavor] = VirtualMachineSize(
            name=pf9_flavor, number_of_cores=1, memory_in_mb=1024)

    def get_instance_info(self, instance_uuid):
        driver = self.driver
        retval = {}
        try:
            instance_name = driver._uuid_to_omni_instance[instance_uuid].name
            azure_instance = utils.get_instance(
                driver.compute_client, drv_conf.resource_group, instance_name)
            instance_status = driver._get_power_state(azure_instance)
            flavor_name = azure_instance.hardware_profile.vm_size
            flavor = driver.flavor_info[flavor_name]
            retval['name'] = azure_instance.name
            retval['power_state'] = instance_status
            retval['instance_uuid'] = instance_uuid
            retval['vcpus'] = flavor.number_of_cores
            retval['memory_mb'] = flavor.memory_in_mb

            bdm = []
            boot_index = 0
            disk_size = azure_instance.storage_profile.os_disk.disk_size_gb
            disk_info = {
                'device_name': '',
                'boot_index': boot_index,
                'guest_format': 'volume',
                'source_type': 'blank',
                'virtual_size': disk_size,
                'destination_type': 'local',
                'snapshot_id': None,
                'volume_id': None,
                'image_id': None,
                'volume_size': None
            }
            bdm.append(disk_info)
            # TODO(ssudake21): Add support for Data disks BDM
            retval['block_device_mapping_v2'] = bdm
            return retval
        except Exception as e:
            LOG.exception('Could not fetch info for %s, error %s' %
                          (instance_uuid, e))
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


def pf9_extend_driver(drv_inst, extension=PF9NovaExtension):
    ext_inst = extension(drv_inst)
    methods = [
        attr for attr in dir(ext_inst)
        if not attr.startswith('__') and callable(getattr(ext_inst, attr))
    ]
    for method in methods:
        setattr(drv_inst, method, getattr(ext_inst, method))
