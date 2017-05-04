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

from cinder.i18n import _LI
# from cinder.exception import VolumeNotFound, NotFound, APITimeout, InvalidConfigurationValue
from cinder.volume.driver import BaseVD
from cinder.volume.drivers.gce import gceconf
from cinder.volume.drivers.gce import gceutils

LOG = logging.getLogger(__name__)


class GceDriver(BaseVD):
    def __init__(self, *args, **kwargs):
        super(GceDriver, self).__init__(*args, **kwargs)
        self.VERSION = '0.0.1'
        self.gce_zone = gceconf.zone
        self.gce_region = gceconf.region
        self.gce_project = gceconf.project_id
        self.gce_svc_key = gceconf.service_key_path

    def do_setup(self, context):
        self.gce_svc = gceutils.get_gce_service(self.gce_svc_key)
        self.set_initialized()
        LOG.info(
            _LI("Gce volume driver init with %s project, %s zone") %
            (self.gce_project, self.gce_zone))

    def _gce_volume_name(self, volume):
        return 'vol-' + volume.id

    def create_volume(self, volume):
        LOG.info('create volume %s %s' % (volume.__dict__, volume))
        compute, project, zone = self.gce_svc, self.gce_project, self.gce_zone
        name = self._gce_volume_name(volume)
        size = volume['size']
        operation = gceutils.create_disk(compute, project, zone, name, size)
        gceutils.wait_for_operation(compute, project, operation)

    def delete_volume(self, volume):
        LOG.info('delete volume %s %s' % (volume.__dict__, volume))
        compute, project, zone = self.gce_svc, self.gce_project, self.gce_zone
        name = self._gce_volume_name(volume)
        operation = gceutils.delete_disk(compute, project, zone, name)
        gceutils.wait_for_operation(compute, project, operation)

    def check_for_setup_error(self):
        pass

    def create_export(self, context, volume, connector):
        pass

    def ensure_export(self, context, volume):
        pass

    def remove_export(self, context, volume):
        pass

    def initialize_connection(self, volume, connector, initiator_data=None):
        compute, project, zone = self.gce_svc, self.gce_project, self.gce_zone
        name = self._gce_volume_name(volume)
        # TODO: Raise exception if volume not found
        gce_volume = gceutils.get_disk(compute, project, zone, name)
        return dict(data=gce_volume)

    def terminate_connection(self, volume, connector, **kwargs):
        pass

    def _update_volume_stats(self):
        data = dict()
        data['volume_backend_name'] = 'gce'
        data['vendor_name'] = 'Google, Inc.'
        data['driver_version'] = '0.0.1'
        data['storage_protocol'] = 'iscsi'
        pool = dict(pool_name='gce', free_capacity_gb=2048,
                    total_capacity_gb=2048, provisioned_capacity_gb=0,
                    reserved_percentage=0, location_info=dict(),
                    QoS_support=False, max_over_subscription_ratio=1.0,
                    thin_provisioning_support=False,
                    thick_provisioning_support=True, total_volumes=0)
        data['pools'] = [pool]
        self._stats = data

    def get_volume_stats(self, refresh=False):
        if refresh:
            self._update_volume_stats()
        return self._stats

    def create_snapshot(self, snapshot):
        LOG.info('create snapshot %s %s' % (snapshot.__dict__, snapshot))
        raise NotImplementedError()

    def delete_snapshot(self, snapshot):
        raise NotImplementedError()

    def create_volume_from_snapshot(self, volume, snapshot):
        raise NotImplementedError()

    def copy_image_to_volume(self, context, volume, image_service, image_id):
        raise NotImplementedError()

    def copy_volume_to_image(self, context, volume, image_service, image_meta):
        raise NotImplementedError()

    def migrate_volume(self, context, volume, host):
        raise NotImplementedError()

    def copy_volume_data(self, context, src_vol, dest_vol, remote=None):
        raise NotImplementedError()
