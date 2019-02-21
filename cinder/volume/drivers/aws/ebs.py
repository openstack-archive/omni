"""
Copyright 2016 Platform9 Systems Inc.(http://www.platform9.com)
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import time

import boto3

from botocore.exceptions import ClientError
from cinder.exception import APITimeout
from cinder.exception import ImageNotFound
from cinder.exception import InvalidConfigurationValue
from cinder.exception import NotFound
from cinder.exception import VolumeBackendAPIException
from cinder.exception import VolumeNotFound
from cinder.volume.driver import BaseVD

from cinder.volume.drivers.aws.config import CONF
from cinder.volume.drivers.aws.credshelper import get_credentials

from oslo_log import log as logging
from oslo_service import loopingcall

LOG = logging.getLogger(__name__)


class EBSDriver(BaseVD):
    """Implements cinder volume interface with EBS as storage backend."""
    def __init__(self, *args, **kwargs):
        super(EBSDriver, self).__init__(*args, **kwargs)
        self.VERSION = '1.0.0'
        self._wait_time_sec = 60 * (CONF.AWS.wait_time_min)

    def do_setup(self, context):
        self._check_config()
        self.az = CONF.AWS.az
        self.set_initialized()

    def _check_config(self):
        tbl = dict([(n, eval(n)) for n in ['CONF.AWS.region_name',
                                           'CONF.AWS.az']])
        for k, v in tbl.iteritems():
            if v is None:
                raise InvalidConfigurationValue(value=None, option=k)

    def _ec2_client(self, context, project_id=None):
        creds = get_credentials(context, project_id=project_id)
        return boto3.client(
            "ec2", region_name=CONF.AWS.region_name,
            aws_access_key_id=creds['aws_access_key_id'],
            aws_secret_access_key=creds['aws_secret_access_key'],)

    def _wait_for_create(self, ec2_conn, ec2_id, final_state,
                         is_snapshot=False):
        def _wait_for_status(start_time):
            current_time = time.time()

            if current_time - start_time > self._wait_time_sec:
                raise loopingcall.LoopingCallDone(False)

            try:
                if is_snapshot:
                    resp = ec2_conn.describe_snapshots(SnapshotIds=[ec2_id])
                    obj = resp['Snapshots'][0]
                else:
                    resp = ec2_conn.describe_volumes(VolumeIds=[ec2_id])
                    obj = resp['Volumes'][0]

                if obj['State'] == final_state:
                    raise loopingcall.LoopingCallDone(True)
            except ClientError as e:
                LOG.warn(e.message)
        timer = loopingcall.FixedIntervalLoopingCall(_wait_for_status,
                                                     time.time())
        return timer.start(interval=10).wait()

    def _wait_for_tags_creation(self, ec2_conn, ec2_id, ostack_obj,
                                is_clone=False, is_snapshot=False):
        def _wait_for_completion(start_time):
            if time.time() - start_time > self._wait_time_sec:
                raise loopingcall.LoopingCallDone(False)
            tags = [
                {'Key': 'project_id', 'Value': ostack_obj['project_id']},
                {'Key': 'uuid', 'Value': ostack_obj['id']},
                {'Key': 'is_clone', 'Value': str(is_clone)},
                {'Key': 'created_at', 'Value': str(ostack_obj['created_at'])},
                {'Key': 'Name', 'Value': ostack_obj['display_name']},
            ]
            ec2_conn.create_tags(Resources=[ec2_id], Tags=tags)
            if is_snapshot:
                resp = ec2_conn.describe_snapshots(SnapshotIds=[ec2_id])
                obj = resp['Snapshots'][0]
            else:
                resp = ec2_conn.describe_volumes(VolumeIds=[ec2_id])
                obj = resp['Volumes'][0]
            if 'Tags' in obj and obj['Tags']:
                raise loopingcall.LoopingCallDone(True)
        timer = loopingcall.FixedIntervalLoopingCall(_wait_for_completion,
                                                     time.time())
        return timer.start(interval=10).wait()

    def create_volume(self, volume):
        size = volume['size']
        ec2_conn = self._ec2_client(
            volume.obj_context, project_id=volume.project_id)
        ebs_vol = ec2_conn.create_volume(Size=size, AvailabilityZone=self.az)
        vol_id = ebs_vol['VolumeId']
        if not self._wait_for_create(ec2_conn, vol_id, 'available'):
            raise APITimeout(service='EC2')
        if not self._wait_for_tags_creation(ec2_conn, vol_id, volume):
            raise APITimeout(service='EC2')

    def delete_volume(self, volume):
        ec2_conn = self._ec2_client(
            volume.obj_context, project_id=volume.project_id)
        try:
            ebs_vol = self._find(volume['id'], ec2_conn.describe_volumes)
        except NotFound:
            LOG.error('Volume %s was not found' % volume['id'])
            return
        ec2_conn.delete_volume(VolumeId=ebs_vol['VolumeId'])

    def _find(self, obj_id, find_func, is_snapshot=False):
        ebs_objs = find_func(Filters=[{'Name': 'tag:uuid',
                                       'Values': [obj_id]}])
        if is_snapshot:
            if len(ebs_objs['Snapshots']) == 0:
                raise NotFound()
            ebs_obj = ebs_objs['Snapshots'][0]
        else:
            if len(ebs_objs['Volumes']) == 0:
                raise NotFound()
            ebs_obj = ebs_objs['Volumes'][0]
        return ebs_obj

    def check_for_setup_error(self):
        # TODO(check_setup_error) throw errors if AWS config is broken
        pass

    def create_export(self, context, volume, connector):
        pass

    def ensure_export(self, context, volume):
        pass

    def remove_export(self, context, volume):
        pass

    def initialize_connection(self, volume, connector, initiator_data=None):
        ec2_conn = self._ec2_client(
            volume.obj_context, project_id=volume.project_id)
        try:
            ebs_vol = self._find(volume.id, ec2_conn.describe_volumes)
        except NotFound:
            raise VolumeNotFound(volume_id=volume.id)
        conn_info = dict(data=dict(volume_id=ebs_vol['VolumeId']))
        return conn_info

    def terminate_connection(self, volume, connector, **kwargs):
        pass

    def _update_volume_stats(self):
        data = dict()
        data['volume_backend_name'] = 'ebs'
        data['vendor_name'] = 'Amazon, Inc.'
        data['driver_version'] = '0.1'
        data['storage_protocol'] = 'iscsi'
        pool = dict(pool_name='ebs',
                    free_capacity_gb=CONF.ebs_free_capacity_gb,
                    total_capacity_gb=CONF.ebs_total_capacity_gb,
                    provisioned_capacity_gb=0,
                    reserved_percentage=0,
                    location_info=dict(),
                    QoS_support=False,
                    max_over_subscription_ratio=1.0,
                    thin_provisioning_support=False,
                    thick_provisioning_support=True,
                    total_volumes=0)
        data['pools'] = [pool]
        self._stats = data

    def get_volume_stats(self, refresh=False):
        if refresh is True:
            self._update_volume_stats()
        return self._stats

    def create_snapshot(self, snapshot):
        vol_id = snapshot['volume_id']
        ec2_conn = self._ec2_client(
            snapshot.obj_context, project_id=snapshot.project_id)
        try:
            ebs_vol = self._find(vol_id, ec2_conn.describe_volumes)
        except NotFound:
            raise VolumeNotFound(volume_id=vol_id)

        ebs_snap = ec2_conn.create_snapshot(VolumeId=ebs_vol['VolumeId'])
        if not self._wait_for_create(ec2_conn, ebs_snap['SnapshotId'],
                                     'completed', is_snapshot=True):
            raise APITimeout(service='EC2')
        if not self._wait_for_tags_creation(ec2_conn, ebs_snap['SnapshotId'],
                                            snapshot, True, True):
            raise APITimeout(service='EC2')

    def delete_snapshot(self, snapshot):
        ec2_conn = self._ec2_client(
            snapshot.obj_context, project_id=snapshot.project_id)
        try:
            ebs_ss = self._find(snapshot['id'], ec2_conn.describe_snapshots,
                                is_snapshot=True)
        except NotFound:
            LOG.error('Snapshot %s was not found' % snapshot['id'])
            return
        ec2_conn.delete_snapshot(SnapshotId=ebs_ss['SnapshotId'])

    def create_volume_from_snapshot(self, volume, snapshot):
        ec2_conn = self._ec2_client(
            volume.obj_context, project_id=volume.project_id)
        try:
            ebs_ss = self._find(snapshot['id'], ec2_conn.describe_snapshots,
                                is_snapshot=True)
        except NotFound:
            LOG.error('Snapshot %s was not found' % snapshot['id'])
            raise
        ebs_vol = ec2_conn.create_volume(AvailabilityZone=self.az,
                                         SnapshotId=ebs_ss['SnapshotId'])
        vol_id = ebs_vol['VolumeId']

        if not self._wait_for_create(ec2_conn, vol_id, 'available'):
            raise APITimeout(service='EC2')
        if not self._wait_for_tags_creation(ec2_conn, vol_id, volume):
            raise APITimeout(service='EC2')

    def create_cloned_volume(self, volume, srcvol_ref):
        ebs_snap = None
        ebs_vol = None
        ec2_conn = self._ec2_client(
            volume.obj_context, project_id=volume.project_id)
        try:
            src_vol = self._find(srcvol_ref['id'], ec2_conn.describe_volumes)
            ebs_snap = ec2_conn.create_snapshot(VolumeId=src_vol['VolumeId'])

            if not self._wait_for_create(ec2_conn, ebs_snap['SnapshotId'],
                                         'completed', is_snapshot=True):
                raise APITimeout(service='EC2')

            ebs_vol = ec2_conn.create_volume(
                Size=volume.size, AvailabilityZone=self.az,
                SnapshotId=ebs_snap['SnapshotId'])
            vol_id = ebs_vol['VolumeId']

            if not self._wait_for_create(ec2_conn, vol_id, 'available'):
                raise APITimeout(service='EC2')
            if not self._wait_for_tags_creation(ec2_conn, vol_id, volume,
                                                True):
                raise APITimeout(service='EC2')
        except NotFound:
            raise VolumeNotFound(srcvol_ref['id'])
        except Exception as ex:
            message = "create_cloned_volume failed! volume: {0}, reason: {1}"
            LOG.error(message.format(volume.id, ex))
            if ebs_vol:
                ec2_conn.delete_volume(VolumeId=ebs_vol['VolumeId'])
            raise VolumeBackendAPIException(data=message.format(volume.id, ex))
        finally:
            if ebs_snap:
                ec2_conn.delete_snapshot(SnapshotId=ebs_snap['SnapshotId'])

    def clone_image(self, context, volume, image_location, image_meta,
                    image_service):
        ec2_conn = self._ec2_client(context, project_id=volume.project_id)
        image_id = image_meta['properties']['aws_image_id']
        snapshot_id = self._get_snapshot_id(ec2_conn, image_id)
        ebs_vol = ec2_conn.create_volume(
            Size=volume.size, AvailabilityZone=self.az,
            SnapshotId=snapshot_id)
        vol_id = ebs_vol['VolumeId']
        if not self._wait_for_create(ec2_conn, vol_id, 'available'):
            raise APITimeout(service='EC2')
        if not self._wait_for_tags_creation(ec2_conn, vol_id, volume, True):
            raise APITimeout(service='EC2')
        metadata = volume['metadata']
        metadata['new_volume_id'] = vol_id
        return dict(metadata=metadata), True

    def _get_snapshot_id(self, ec2_conn, image_id):
        try:
            resp = ec2_conn.describe_images(ImageIds=[image_id])
            ec2_image = resp['Images'][0]
            snapshot_id = None
            for bdm in ec2_image['BlockDeviceMappings']:
                if bdm['DeviceName'] == '/dev/sda1':
                    snapshot_id = bdm['Ebs']['SnapshotId']
                    break
            return snapshot_id
        except ClientError as e:
            message = "Getting image {0} failed. Error: {1}"
            LOG.error(message.format(image_id, e.message))
            raise ImageNotFound(message.format(image_id, e.message))

    def copy_image_to_volume(self, context, volume, image_service, image_id):
        """Nothing need to do here since we create volume from image in
        clone_image.
        """
        pass

    def copy_volume_to_image(self, context, volume, image_service, image_meta):
        raise NotImplemented()

    def migrate_volume(self, context, volume, host):
        raise NotImplemented()

    def copy_volume_data(self, context, src_vol, dest_vol, remote=None):
        """Nothing need to do here since we create volume from another
        volume in create_cloned_volume.
        """
        pass
