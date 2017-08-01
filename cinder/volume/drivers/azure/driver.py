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

from cinder.volume.driver import BaseVD
from cinder.volume.drivers.azure import config
from cinder.volume.drivers.azure import utils
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class AzureDriver(BaseVD):
    def __init__(self, *args, **kwargs):
        super(AzureDriver, self).__init__(*args, **kwargs)
        self.VERSION = '0.0.1'
        self.tenant_id = config.tenant_id
        self.client_id = config.client_id
        self.client_secret = config.client_secret
        self.subscription_id = config.subscription_id
        self.region = config.region
        self.resource_group = config.resource_group

    def do_setup(self, context):
        self.compute = utils.get_azure_client(
            self.tenant_id, self.client_id, self.client_secret,
            self.subscription_id)
        self.set_initialized()
        LOG.debug("Azure volume driver init with %s tenant_id" %
                  self.tenant_id)

    def _azure_volume_name(self, volume):
        return 'vol-' + volume.id

    def _azure_snapshot_name(self, snapshot):
        return 'snap-' + snapshot.id

    def _validate_operation(self, name, volume_flag, delete_flag=False):
        # Validates creation/deletion operations of snapshot and volume
        # In case of deletion, 'get' function is supposed to raise an Exception
        # as volume/snapshot will not be available. Hence ignoring it in
        # except block.
        try:
            if volume_flag:
                _ = utils.get_disk(self.compute, self.resource_group, name)
            else:
                _ = utils.get_snapshot(self.compute, self.resource_group, name)
        except Exception as e:
            if not delete_flag:
                raise Exception(e)

    def create_volume(self, volume):
        volume_name = self._azure_volume_name(volume)
        utils.create_disk(self.compute, self.resource_group,
                          self.region, volume_name, volume['size'])
        self._validate_operation(volume_name, True)

    def delete_volume(self, volume):
        volume_name = self._azure_volume_name(volume)
        utils.delete_disk(self.compute, self.resource_group, volume_name)
        self._validate_operation(volume_name, True, True)

    def create_snapshot(self, snapshot):
        volume_name = self._azure_volume_name(snapshot.volume)
        snapshot_name = self._azure_snapshot_name(snapshot)
        utils.snapshot_disk(self.compute, self.resource_group,
                            self.region, volume_name, snapshot_name)
        self._validate_operation(snapshot_name, False)

    def delete_snapshot(self, snapshot):
        snapshot_name = self._azure_snapshot_name(snapshot)
        utils.delete_snapshot(self.compute, self.resource_group, snapshot_name)
        self._validate_operation(snapshot_name, False, True)

    def create_volume_from_snapshot(self, volume, snapshot):
        volume_name = self._azure_volume_name(volume)
        snapshot_name = self._azure_snapshot_name(snapshot)
        utils.create_disk_from_snapshot(self.compute, self.resource_group,
                                        self.region, volume_name,
                                        snapshot_name)
        self._validate_operation(volume_name, True, False)

    def get_volume_stats(self, refresh=False):
        if refresh:
            data = dict()
            data['volume_backend_name'] = 'azure',
            data['vendor_name'] = 'Azure',
            data['driver_version'] = '0.0.1',
            data['storage_protocol'] = 'iscsi',
            pool = dict(pool_name=config.azure_pool_name,
                        free_capacity_gb=config.azure_free_capacity_gb,
                        total_capacity_gb=config.azure_free_capacity_gb,
                        provisioned_capacity_gb=0, reserved_percentage=0,
                        location_info=dict(), QoS_support=False,
                        max_over_subscription_ratio=1.0,
                        thin_provisioning_support=False,
                        thick_provisioning_support=True, total_volumes=0)
            data['pools'] = [pool]
            self._stats = data
        return self._stats

    def check_for_setup_error(self):
        pass

    def ensure_export(self, context, volume):
        pass

    def create_export(self, context, volume, connector):
        pass

    def remove_export(self, context, volume):
        pass

    def initialize_connection(self, volume, connector, **kwargs):
        volume_name = self._azure_volume_name(volume)
        azure_volume = utils.get_disk(self.compute, self.resource_group,
                                      volume_name)
        return dict(data=azure_volume)

    def terminate_connection(self, volume, connector, **kwargs):
        pass

    def copy_image_to_volume(self, context, volume, image_service, image_id):
        raise NotImplementedError()

    def copy_volume_to_image(self, context, volume, image_service, image_meta):
        raise NotImplementedError()

    def migrate_volume(self, context, volume, host):
        raise NotImplementedError()

    def copy_volume_data(self, context, src_vol, dest_vol, remote=None):
        raise NotImplementedError()
