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
from cinder.volume.drivers.azure import azureutils
from cinder.volume.drivers.azure import config
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class AzureDriver(BaseVD):
    def __init__(self, *args, **kwargs):
        super(AzureDriver, self).__init__(*args, **kwargs)
        self.tenant_id = config.tenant_id
        self.client_id = config.client_id
        self.client_secret = config.client_secret
        self.subscription_id = config.subscription_id
        self.region = config.region
        self.resource_group = config.resource_group

    def do_setup(self, context):
        args = (self.tenant_id, self.client_id, self.client_secret,
                self.subscription_id)
        self.management_client = azureutils.get_management_client(*args)
        self.resource_client = azureutils.get_resource_client(*args)
        is_resource_created = azureutils.check_resource_existence(
            self.resource_client, self.resource_group)
        if not is_resource_created:
            azureutils.create_resource_group(
                self.resource_client, self.resource_group, self.region)
        self.set_initialized()
        LOG.info("Azure volume driver init with %s tenant_id" %
                 self.tenant_id)

    def _azure_volume_name(self, volume):
        return 'vol-' + volume.id

    def _azure_snapshot_name(self, snapshot):
        return 'snap-' + snapshot.id

    def create_volume(self, volume):
        volume_name = self._azure_volume_name(volume)
        azureutils.create_disk(self.management_client, self.resource_group,
                               self.region, volume_name, volume['size'])

    def create_volume_from_snapshot(self, volume, snapshot):
        volume_name = self._azure_volume_name(volume)
        snapshot_name = self._azure_snapshot_name(snapshot)
        azureutils.create_disk_from_snapshot(
            self.management_client, self.resource_group, self.region,
            volume_name, snapshot_name)

    def create_cloned_volume(self, volume, src_vref):
        azureutils.create_disk_from_disk(
            self.management_client, self.resource_group,
            self.region, src_vref, volume)

    def delete_volume(self, volume):
        volume_name = self._azure_volume_name(volume)
        azureutils.delete_disk(self.management_client, self.resource_group,
                               volume_name)

    def create_snapshot(self, snapshot):
        volume_name = self._azure_volume_name(snapshot.volume)
        snapshot_name = self._azure_snapshot_name(snapshot)
        azureutils.snapshot_disk(self.management_client, self.resource_group,
                                 self.region, volume_name, snapshot_name)

    def delete_snapshot(self, snapshot):
        snapshot_name = self._azure_snapshot_name(snapshot)
        azureutils.delete_snapshot(
            self.management_client, self.resource_group, snapshot_name)

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
        azure_volume = azureutils.get_disk(
            self.management_client, self.resource_group, volume_name)
        return dict(data=azure_volume)

    def terminate_connection(self, volume, connector, **kwargs):
        pass

    def copy_image_to_volume(self, context, volume, image_service, image_id):
        raise NotImplementedError("Azure does not support this operation")

    def copy_volume_to_image(self, context, volume, image_service, image_meta):
        raise NotImplementedError("Azure does not support this operation")

    def migrate_volume(self, context, volume, host):
        raise NotImplementedError("Azure does not support this operation")

    def copy_volume_data(self, context, src_vol, dest_vol, remote=None):
        """Nothing need to do here since we create volume from volume in
        create_cloned_volume.
        """
        pass
