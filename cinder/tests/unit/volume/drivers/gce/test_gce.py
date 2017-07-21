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

import mock
import os

from cinder import context
from cinder import test
from cinder.tests.unit.fake_snapshot import fake_snapshot_obj
from cinder.tests.unit.fake_volume import fake_volume_obj
from cinder.tests.unit.volume.drivers.gce import gce_mock
from cinder.volume.drivers.gce.driver import GceDriver
from cinder.volume.drivers.gce.gceutils import GceOperationError

DATA_DIR = os.path.dirname(os.path.abspath(__file__)) + '/data'


class GCEVolumeTestCase(test.TestCase):
    @mock.patch('cinder.volume.drivers.gce.driver.gceutils.get_gce_service')
    def setUp(self, mock_service):
        mock_service.side_effect = gce_mock.get_gce_service
        super(GCEVolumeTestCase, self).setUp()
        self._driver = GceDriver()
        self._driver.gce_zone = 'us-central1-c'
        self._driver.gce_region = 'us-central1'
        self._driver.gce_project = 'omni-163105'
        self._driver.gce_svc_key = "{0}/omni.json".format(DATA_DIR)
        self.test_context = context.get_admin_context()
        self.fake_volume = fake_volume_obj(self.test_context)
        self.fake_snapshot = fake_snapshot_obj(self.test_context)
        self.fake_snapshot.volume = self.fake_volume
        self._driver.do_setup(self.test_context)

    @mock.patch('cinder.volume.drivers.gce.driver.gceutils.wait_for_operation')
    @mock.patch('cinder.volume.drivers.gce.driver.gceutils.create_disk')
    def _create_volume(self, mock_disk, mock_wait):
        mock_disk.side_effect = gce_mock.create_anything
        mock_wait.side_effect = gce_mock.wait_for_operation
        self._driver.create_volume(self.fake_volume)
        mock_wait.assert_called_once_with(self._driver.gce_svc,
                                          self._driver.gce_project,
                                          gce_mock.fake_operation())

    @mock.patch('cinder.volume.drivers.gce.driver.gceutils.wait_for_operation')
    @mock.patch('cinder.volume.drivers.gce.driver.gceutils.snapshot_disk')
    def _create_snapshot(self, mock_snapshot, mock_wait):
        mock_snapshot.side_effect = gce_mock.create_anything
        mock_wait.side_effect = gce_mock.wait_for_operation
        self._driver.create_snapshot(self.fake_snapshot)
        mock_wait.assert_called_once_with(self._driver.gce_svc,
                                          self._driver.gce_project,
                                          gce_mock.fake_operation())

    def test_volume_create_success(self):
        self.assertIsNone(self._create_volume())

    @mock.patch('cinder.volume.drivers.gce.driver.gceutils.wait_for_operation')
    @mock.patch('cinder.volume.drivers.gce.driver.gceutils.delete_disk')
    def test_volume_deletion_success(self, mock_disk, mock_wait):
        mock_disk.side_effect = gce_mock.delete_anything
        mock_wait.side_effect = gce_mock.wait_for_operation
        self.assertIsNone(self._driver.delete_volume(self.fake_volume))
        mock_wait.assert_called_once_with(self._driver.gce_svc,
                                          self._driver.gce_project,
                                          gce_mock.fake_operation())

    @mock.patch('cinder.volume.drivers.gce.driver.gceutils.wait_for_operation')
    @mock.patch('cinder.volume.drivers.gce.driver.gceutils.create_disk')
    def test_volume_deletion_failure(self, mock_disk, mock_wait):
        mock_disk.side_effect = gce_mock.create_anything
        mock_wait.side_effect = GceOperationError
        self.assertRaises(GceOperationError, self._driver.delete_volume,
                          self.fake_volume)

    def test_create_snapshot(self):
        self._create_volume()
        self.assertIsNone(self._create_snapshot())

    @mock.patch('cinder.volume.drivers.gce.driver.gceutils.wait_for_operation')
    @mock.patch('cinder.volume.drivers.gce.driver.gceutils.delete_snapshot')
    def test_delete_snapshot(self, mock_snapshot, mock_wait):
        mock_snapshot.side_effect = gce_mock.delete_anything
        mock_wait.side_effect = gce_mock.wait_for_operation
        self.assertIsNone(self._driver.delete_snapshot(self.fake_snapshot))
        mock_wait.assert_called_once_with(self._driver.gce_svc,
                                          self._driver.gce_project,
                                          gce_mock.fake_operation())

    @mock.patch('cinder.volume.drivers.gce.driver.gceutils.wait_for_operation')
    @mock.patch(
        'cinder.volume.drivers.gce.driver.gceutils.create_disk_from_snapshot')
    @mock.patch('cinder.volume.drivers.gce.driver.gceutils.get_snapshot')
    def test_create_volume_from_snapshot(self, mock_get_snapshot,
                                         mock_snapshot, mock_wait):
        mock_get_snapshot.side_effect = gce_mock.get_snapshot
        mock_snapshot.side_effect = gce_mock.create_anything
        mock_wait.side_effect = gce_mock.wait_for_operation
        self.assertIsNone(
            self._driver.create_volume_from_snapshot(self.fake_volume,
                                                     self.fake_snapshot))
        mock_wait.assert_called_once_with(self._driver.gce_svc,
                                          self._driver.gce_project,
                                          gce_mock.fake_operation())
