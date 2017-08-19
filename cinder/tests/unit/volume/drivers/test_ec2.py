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

from cinder import context
from cinder.exception import APITimeout
from cinder.exception import ImageNotFound
from cinder.exception import NotFound
from cinder.exception import SnapshotUnavailable
from cinder.exception import VolumeNotFound
from cinder import test
from cinder.tests.unit.fake_volume import fake_volume_obj
from cinder.volume.drivers.aws import ebs
from cinder.volume.drivers.aws.exception import AvailabilityZoneNotFound
import mock
from moto import mock_ec2
from oslo_service import loopingcall


class EBSVolumeTestCase(test.TestCase):
    @mock_ec2
    def setUp(self):
        super(EBSVolumeTestCase, self).setUp()
        ebs.CONF.AWS.region_name = 'us-east-1'
        ebs.CONF.AWS.access_key = 'fake-key'
        ebs.CONF.AWS.secret_key = 'fake-secret'
        ebs.CONF.AWS.az = 'us-east-1a'
        self._driver = ebs.EBSDriver()
        self.ctxt = context.get_admin_context()
        self._driver.do_setup(self.ctxt)

    def _stub_volume(self, **kwargs):
        uuid = u'c20aba21-6ef6-446b-b374-45733b4883ba'
        name = u'volume-00000001'
        size = 1
        created_at = '2016-10-19 23:22:33'
        volume = dict()
        volume['id'] = kwargs.get('id', uuid)
        volume['display_name'] = kwargs.get('display_name', name)
        volume['size'] = kwargs.get('size', size)
        volume['provider_location'] = kwargs.get('provider_location', None)
        volume['volume_type_id'] = kwargs.get('volume_type_id', None)
        volume['project_id'] = kwargs.get('project_id', 'aws_proj_700')
        volume['created_at'] = kwargs.get('create_at', created_at)
        return volume

    def _stub_snapshot(self, **kwargs):
        uuid = u'0196f961-c294-4a2a-923e-01ef5e30c2c9'
        created_at = '2016-10-19 23:22:33'
        ss = dict()

        ss['id'] = kwargs.get('id', uuid)
        ss['project_id'] = kwargs.get('project_id', 'aws_proj_700')
        ss['created_at'] = kwargs.get('create_at', created_at)
        ss['volume'] = kwargs.get('volume', self._stub_volume())
        ss['display_name'] = kwargs.get('display_name', 'snapshot_007')
        return ss

    def _fake_image_meta(self):
        image_meta = dict()
        image_meta['properties'] = {}
        image_meta['status'] = 'active'
        image_meta['name'] = 'fake_image_name'
        image_meta['container_format'] = 'ami'
        image_meta['created_at'] = '2016-10-19 23:22:33'
        image_meta['disk_format'] = 'ami'
        image_meta['id'] = 'b2a55a41-7f8b-5ad8-7de9-84309d5108a2'
        image_meta['properties']['aws_image_id'] = 'ami-00001'
        return image_meta

    @mock_ec2
    def test_availability_zone_config(self):
        ebs.CONF.AWS.az = 'hgkjhgkd'
        driver = ebs.EBSDriver()
        self.assertRaises(AvailabilityZoneNotFound, driver.do_setup, self.ctxt)
        ebs.CONF.AWS.az = 'us-east-1a'

    @mock_ec2
    def test_volume_create_success(self):
        self.assertIsNone(self._driver.create_volume(self._stub_volume()))

    @mock_ec2
    @mock.patch('cinder.volume.drivers.aws.ebs.EBSDriver._wait_for_create')
    def test_volume_create_fails(self, mock_wait):
        def wait(*args):
            def _wait():
                raise loopingcall.LoopingCallDone(False)

            timer = loopingcall.FixedIntervalLoopingCall(_wait)
            return timer.start(interval=1).wait()

        mock_wait.side_effect = wait
        self.assertRaises(APITimeout, self._driver.create_volume,
                          self._stub_volume())

    @mock_ec2
    def test_volume_deletion(self):
        vol = self._stub_volume()
        self._driver.create_volume(vol)
        self.assertIsNone(self._driver.delete_volume(vol))

    @mock_ec2
    @mock.patch('cinder.volume.drivers.aws.ebs.EBSDriver._find')
    def test_volume_deletion_not_found(self, mock_find):
        vol = self._stub_volume()
        mock_find.side_effect = NotFound
        self.assertIsNone(self._driver.delete_volume(vol))

    @mock_ec2
    def test_snapshot(self):
        vol = self._stub_volume()
        snapshot = self._stub_snapshot()
        self._driver.create_volume(vol)
        self.assertIsNone(self._driver.create_snapshot(snapshot))

    @mock_ec2
    @mock.patch('cinder.volume.drivers.aws.ebs.EBSDriver._find')
    def test_snapshot_volume_not_found(self, mock_find):
        mock_find.side_effect = NotFound
        ss = self._stub_snapshot()
        self.assertRaises(VolumeNotFound, self._driver.create_snapshot, ss)

    @mock_ec2
    @mock.patch('cinder.volume.drivers.aws.ebs.EBSDriver._wait_for_snapshot')
    def test_snapshot_create_fails(self, mock_wait):
        def wait(*args):
            def _wait():
                raise loopingcall.LoopingCallDone(False)

            timer = loopingcall.FixedIntervalLoopingCall(_wait)
            return timer.start(interval=1).wait()

        mock_wait.side_effect = wait
        ss = self._stub_snapshot()
        self._driver.create_volume(ss['volume'])
        self.assertRaises(APITimeout, self._driver.create_snapshot, ss)

    @mock_ec2
    def test_volume_from_snapshot(self):
        snapshot = self._stub_snapshot()
        volume = self._stub_volume()
        self._driver.create_volume(volume)
        self._driver.create_snapshot(snapshot)
        self.assertIsNone(
            self._driver.create_volume_from_snapshot(volume, snapshot))

    @mock_ec2
    def test_volume_from_non_existing_snapshot(self):
        self.assertRaises(NotFound, self._driver.create_volume_from_snapshot,
                          self._stub_volume(), self._stub_snapshot())

    def test_clone_image_with_invalid_image(self):
        image_meta = self._fake_image_meta()
        volume = fake_volume_obj(self.ctxt)
        self.assertRaises(ImageNotFound, self._driver.clone_image,
                          self.ctxt, volume, '', image_meta, '')

    @mock_ec2
    @mock.patch('cinder.volume.drivers.aws.ebs.EBSDriver._get_snapshot_id')
    def test_clone_image_with_no_snapshot(self, mock_get):
        mock_get.return_value = None
        image_meta = self._fake_image_meta()
        volume = fake_volume_obj(self.ctxt)
        self.assertRaises(SnapshotUnavailable, self._driver.clone_image,
                          self.ctxt, volume, '', image_meta, '')
        self.assertTrue(mock_get.called)
        mock_get.assert_called_once_with(image_meta['properties'][
            'aws_image_id'])

    @mock_ec2
    @mock.patch('cinder.volume.drivers.aws.ebs.EBSDriver._get_snapshot_id')
    def test_clone_image(self, mock_get):
        snapshot = self._stub_snapshot()
        image_meta = self._fake_image_meta()
        volume = fake_volume_obj(self.ctxt)
        volume.id = 'd30aba21-6ef6-446b-b374-45733b4883ba'
        volume.display_name = 'volume-00000001'
        volume.project_id = 'fake_project_id'
        volume.created_at = '2016-10-19 23:22:33'
        self._driver.create_volume(snapshot['volume'])
        self._driver.create_snapshot(snapshot)
        ebs_snap = self._driver._find(snapshot['id'],
                                      self._driver._conn.get_all_snapshots)
        mock_get.return_value = ebs_snap.id
        metadata, cloned = self._driver.clone_image(self.ctxt, volume, '',
                                                    image_meta, '')
        self.assertEqual(True, cloned)
        self.assertTrue(isinstance(metadata, dict))

    @mock_ec2
    def test_create_cloned_volume(self):
        src_volume = fake_volume_obj(self.ctxt)
        src_volume.display_name = 'volume-00000001'
        src_volume.created_at = '2016-10-19 23:22:33'
        src_volume.project_id = 'fake_project_id'
        volume = fake_volume_obj(self.ctxt)
        volume.id = 'd30aba21-6ef6-446b-b374-45733b4883ba'
        volume.display_name = 'volume-00000002'
        volume.project_id = 'fake_project_id'
        volume.created_at = '2016-10-19 23:23:33'
        self._driver.create_volume(src_volume)
        self.assertIsNone(self._driver.create_cloned_volume(volume,
                                                            src_volume))
