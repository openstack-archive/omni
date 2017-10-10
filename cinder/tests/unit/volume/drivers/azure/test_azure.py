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

import uuid

from azure.mgmt.compute import models as compute_models
from azure.mgmt.compute.models import DiskCreateOption
from azure.mgmt.resource.resources import models as resource_models
from cinder import context
from cinder import exception
from cinder import test
from cinder.tests.unit.fake_snapshot import fake_snapshot_obj
from cinder.tests.unit.fake_volume import fake_volume_obj
from cinder.volume.drivers.azure.driver import AzureDriver
from devtools_testutils.mgmt_testcase import fake_settings

import mock

RESOURCE_GROUP = 'omni_test_group'
CLIENT_SECRET = 'fake_key'


def get_fake_credentials(tenant_id, client_id, client_secret):
    return fake_settings.get_credentials()


def _get_disk():
    creation_data = compute_models.CreationData(
        create_option=DiskCreateOption.empty)
    volume = compute_models.Disk(
        location='eastus', creation_data=creation_data, disk_size_gb=1)
    return volume


def get_fake_volume(client, resource_group, disk_name):
    return _get_disk()


def get_fake_snapshot(client, resource_group, snapshot_name):
    volume = get_fake_volume(client, resource_group, "fake_disk")
    creation_data = compute_models.CreationData(
        create_option=DiskCreateOption.copy, source_uri=volume.id)
    snapshot = compute_models.Snapshot(
        location='eastus', creation_data=creation_data)
    return snapshot


def get_fake_image(compute, resource_group, name):
    storage_profile = compute_models.ImageStorageProfile(
        compute_models.ImageOSDisk('Linux', 'Generalized'))
    image = compute_models.Image(location='eastus')
    image.storage_profile = storage_profile
    managed_disk = compute_models.SubResource(id=str(uuid.uuid4()))
    image.storage_profile.os_disk.managed_disk = managed_disk
    return image


def get_fake_resource_group(client, resource_group):
    resource_group = resource_models.Resource(location='eastus')
    return resource_group


def create_anything(*args, **kwargs):
    return None


def delete_anything(*args, **kwargs):
    return None


def clone_anything(*args, **kwargs):
    volume = _get_disk()
    volume.id = str(uuid.uuid4())
    return volume


class AzureCinderTestCase(test.TestCase):
    @mock.patch(
        "cinder.volume.drivers.azure.azureutils.check_resource_existence")
    def setUp(self, mock_check):
        super(AzureCinderTestCase, self).setUp()
        mock_check.side_effect = get_fake_resource_group
        self.creds_patcher = mock.patch(
            'cinder.volume.drivers.azure.azureutils._get_credentials').start()
        mock_creds = self.creds_patcher.start()
        mock_creds.side_effect = get_fake_credentials
        self.addCleanup(self.creds_patcher.stop)
        self.driver = AzureDriver()
        self.driver.tenant_id = fake_settings.TENANT_ID
        self.driver.client_id = fake_settings.CLIENT_OID
        self.driver.client_secret = CLIENT_SECRET
        self.driver.subscription_id = fake_settings.SUBSCRIPTION_ID
        self.driver.region = "eastus"
        self.driver.resource_group = RESOURCE_GROUP
        self.context = context.get_admin_context()
        self.fake_volume = fake_volume_obj(self.context)
        self.fake_snapshot = fake_snapshot_obj(self.context)
        self.fake_snapshot.volume = self.fake_volume
        self.driver.do_setup(self.context)

    @mock.patch("cinder.volume.drivers.azure.azureutils.create_disk")
    def test_create_empty_volume(self, mock_create):
        mock_create.side_effect = create_anything
        self.assertIsNone(self.driver.create_volume(self.fake_volume))
        mock_create.assert_called_once_with(
            self.driver.management_client, self.driver.resource_group,
            self.driver.region, "vol-" + self.fake_volume['id'],
            self.fake_volume['size'])

    def test_create_empty_volume_failure(self):
        self.assertRaises(exception.VolumeBackendAPIException,
                          self.driver.create_volume, self.fake_volume)

    @mock.patch(
        "cinder.volume.drivers.azure.azureutils.create_disk_from_snapshot")
    def test_create_volume_from_snapshot(self, mock_create):
        mock_create.side_effect = create_anything
        self.assertIsNone(self.driver.create_volume_from_snapshot(
            self.fake_volume, self.fake_snapshot))
        mock_create.assert_called_once_with(
            self.driver.management_client, self.driver.resource_group,
            self.driver.region, "vol-" + self.fake_volume['id'],
            "snap-" + self.fake_snapshot['id'])

    @mock.patch("cinder.volume.drivers.azure.azureutils.get_snapshot")
    def test_create_volume_from_snapshot_failure(self, mock_get):
        mock_get.side_effect = get_fake_snapshot
        self.assertRaises(
            exception.VolumeBackendAPIException,
            self.driver.create_volume_from_snapshot,
            self.fake_volume, self.fake_snapshot)
        self.assertTrue(mock_get.called)

    @mock.patch("cinder.volume.drivers.azure.azureutils.create_disk_from_disk")
    def test_create_cloned_volume(self, mock_create):
        mock_create.side_effect = create_anything
        volume_src = fake_volume_obj(self.context)
        volume_src['id'] = str(uuid.uuid4())
        self.assertIsNone(self.driver.create_cloned_volume(
            self.fake_volume, volume_src))
        mock_create.assert_called_once_with(
            self.driver.management_client, self.driver.resource_group,
            self.driver.region, volume_src, self.fake_volume)

    @mock.patch("cinder.volume.drivers.azure.azureutils.get_disk")
    def test_create_cloned_volume_failure(self, mock_get):
        mock_get.side_effect = get_fake_volume
        volume_src = fake_volume_obj(self.context)
        volume_src['id'] = str(uuid.uuid4())
        self.assertRaises(
            exception.VolumeBackendAPIException,
            self.driver.create_cloned_volume,
            self.fake_volume, volume_src)
        self.assertTrue(mock_get.called)

    @mock.patch(
        "cinder.volume.drivers.azure.azureutils.create_disk_from_image")
    def test_clone_image(self, mock_create):
        mock_create.side_effect = clone_anything
        metadata, cloned = self.driver.clone_image(
            self.context, self.fake_volume, "", {}, "")
        self.assertIsInstance(metadata, dict)
        self.assertTrue(cloned)
        mock_create.assert_called_once_with(
            self.driver.management_client, self.driver.resource_group,
            self.driver.region, {}, self.fake_volume)

    @mock.patch("cinder.volume.drivers.azure.azureutils.get_image")
    def test_clone_image_failure(self, mock_get):
        mock_get.side_effect = get_fake_image
        self.assertRaises(
            exception.VolumeBackendAPIException,
            self.driver.clone_image,
            self.context, self.fake_volume, "", {"name": "fake_image"}, "")

    @mock.patch("cinder.volume.drivers.azure.azureutils.delete_disk")
    def test_delete_volume(self, mock_delete):
        mock_delete.side_effect = delete_anything
        self.assertIsNone(self.driver.delete_volume(self.fake_volume))
        mock_delete.assert_called_once_with(
            self.driver.management_client, self.driver.resource_group,
            "vol-" + self.fake_volume['id'])

    @mock.patch("cinder.volume.drivers.azure.azureutils.get_disk")
    def test_delete_volume_failure(self, mock_get):
        mock_get.side_effect = get_fake_volume
        self.assertRaises(
            exception.VolumeBackendAPIException,
            self.driver.delete_volume, self.fake_volume)

    @mock.patch("cinder.volume.drivers.azure.azureutils.snapshot_disk")
    def test_create_snapshot(self, mock_create):
        mock_create.side_effect = create_anything
        self.assertIsNone(self.driver.create_snapshot(self.fake_snapshot))
        mock_create.assert_called_once_with(
            self.driver.management_client, self.driver.resource_group,
            self.driver.region, "vol-" + self.fake_volume['id'],
            "snap-" + self.fake_snapshot['id'])

    def test_create_snapshot_failure(self):
        self.assertRaises(exception.VolumeBackendAPIException,
                          self.driver.create_snapshot, self.fake_snapshot)

    @mock.patch("cinder.volume.drivers.azure.azureutils.delete_snapshot")
    def test_delete_snapshot(self, mock_delete):
        mock_delete.side_effect = delete_anything
        self.assertIsNone(self.driver.delete_snapshot(self.fake_snapshot))
        mock_delete.assert_called_once_with(
            self.driver.management_client, self.driver.resource_group,
            "snap-" + self.fake_snapshot['id'])

    @mock.patch("cinder.volume.drivers.azure.azureutils.get_snapshot")
    def test_delete_snapshot_failure(self, mock_get):
        mock_get.side_effect = get_fake_snapshot
        self.assertRaises(
            exception.VolumeBackendAPIException,
            self.driver.delete_snapshot, self.fake_snapshot)
