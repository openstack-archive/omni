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

from cinder import context
from cinder import exception
from cinder import test
from cinder.tests.unit.fake_snapshot import fake_snapshot_obj
from cinder.tests.unit.fake_volume import fake_volume_obj
from cinder.tests.unit.volume.drivers.azure import azure_mock
from cinder.volume.drivers.azure.driver import AzureDriver
from msrestazure.azure_exceptions import CloudError


class AzureVolumeTestCase(test.TestCase):

    def setUp(self):
        super(AzureVolumeTestCase, self).setUp()
        self._driver = AzureDriver()
        self._driver.tenant_id = "fake_tenant_id"
        self._driver.client_id = "fake_client_id"
        self._driver.client_secret = "fake_client_secret"
        self._driver.subscription_id = "fake_subscription_id"
        self._driver.zone = 'eastus'
        self._driver.resource_group = 'fake_resource_group'
        self.context = context.get_admin_context()
        self.fake_volume = fake_volume_obj(self.context)
        self.fake_snapshot = fake_snapshot_obj(self.context)
        self.fake_snapshot.volume = self.fake_volume
        self._driver.do_setup(self.context)

    @mock.patch('cinder.volume.drivers.azure.utils.delete_disk')
    @mock.patch('cinder.volume.drivers.azure.utils.create_disk_from_snapshot')
    def test_create_disk_from_snapshot(self, mock_create, mock_delete):
        mock_create.side_effect = azure_mock.create_anything
        mock_delete.side_effect = azure_mock.delete_anything
        self._driver.create_volume_from_snapshot(self.fake_volume,
                                                 self.fake_snapshot)
        self._driver.compute.snapshots.get.assert_called()
        self._driver.compute.disks.create_or_update.assert_called()
        self._driver.delete_volume(self.fake_volume)

    def test_disk_create_failure_with_invalid_disk_size(self):
        self.fake_volume.size = 5000
        self.assertRaises(CloudError, self._driver.create_volume,
                          self.fake_volume)

    @mock.patch('cinder.volume.drivers.azure.utils.create_disk')
    def test_disk_create_success(self, mock_create):
        mock_create.side_effect = azure_mock.create_anything
        self._driver.create_volume(self.fake_volume)
        self._driver.compute.disks.create_or_update.assert_called()

    @mock.patch('cinder.volume.drivers.azure.utils.delete_disk')
    def test_disk_delete(self, mock_delete):
        mock_delete.side_effect = azure_mock.delete_anything
        self._driver.delete_volume(self.fake_volume)
        self._driver.compute.disks.delete.assert_called()

    def test_empty_methods_implement(self):
        self.driver.check_for_setup_error()
        self.driver.ensure_export(self.context, self.fake_volume)
        self.driver.create_export(self.context, self.fake_volume, 'conn')
        self.driver.remove_export(self.context, self.fake_volume)
        self.driver.terminate_connection(self.fake_volume, 'conn')

    @mock.patch('cinder.volume.drivers.azure.utils.snapshot_disk')
    def test_snapshot_create_failure(self, mock_snapshot):
        mock_snapshot.side_effect = azure_mock.create_anything
        self.assertRaises(exception.VolumeBackendAPIException,
                          self._driver.create_snapshot, self.fake_snapshot)

    @mock.patch('cinder.volume.drivers.azure.utils.delete_disk')
    @mock.patch('cinder.volume.drivers.azure.utils.snapshot_disk')
    @mock.patch('cinder.volume.drivers.azure.utils.create_disk')
    def test_snapshot_create_success(self, mock_create, mock_snapshot,
                                     mock_delete):
        mock_create.side_effect = azure_mock.create_anything
        mock_snapshot.side_effect = azure_mock.create_anything
        mock_delete.side_effect = azure_mock.delete_anything
        self._driver.create_volume(self.fake_volume)
        self._driver.create_snapshot(self.fake_snapshot)
        self._driver.compute.snapshots.create_or_update.assert_called()
        self._driver.delete_volume(self.fake_volume)
        self._driver.compute.disks.delete.assert_called()

    @mock.patch('cinder.volume.drivers.azure.utils.delete_snapshot')
    def test_snapshot_delete(self, mock_delete):
        mock_delete.side_effect = azure_mock.delete_anything
        self._driver.delete_snapshot(self.fake_snapshot)
        self._driver.compute.snapshots.delete.assert_called()
