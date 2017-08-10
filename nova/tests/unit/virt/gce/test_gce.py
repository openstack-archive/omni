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

from nova import context
from nova import exception
from nova import test
from nova.tests.unit import fake_instance
from nova.tests.unit.virt.gce import gce_mock
from nova.tests.unit.virt.gce.gce_mock import FakeImageService
from nova.virt import fake
from nova.virt.gce.driver import GCEDriver

DATA_DIR = os.path.dirname(os.path.abspath(__file__)) + '/data'


class GCENovaTestCase(test.TestCase):
    @mock.patch('nova.virt.gce.driver.gceutils.get_machines_info')
    @mock.patch('nova.virt.gce.driver.gceutils.get_gce_service')
    def setUp(self, mock_service, mock_machine_info):
        mock_service.side_effect = gce_mock.get_gce_service
        mock_machine_info.side_effect = gce_mock.get_machines_info
        super(GCENovaTestCase, self).setUp()
        self._driver = GCEDriver(fake.FakeVirtAPI())
        self._driver.gce_zone = 'us-central1-c'
        self._driver.gce_project = 'omni-163105'
        self._driver.gce_svc_key = "{0}/omni.json".format(DATA_DIR)
        self.context = context.get_admin_context()
        self.instance = fake_instance.fake_instance_obj(self.context)
        self.instance.system_metadata = {'image_gce_link': 'fake_link'}
        self.instance.metadata = {'gce_id': "instance-1"}
        self.instance.display_name = "fake_instance"
        self.instance.flavor.name = "n1-standard-1"
        self._driver.init_host(None)

    @mock.patch('nova.virt.gce.driver.gceutils.get_instances_metadata_key')
    @mock.patch('nova.virt.gce.driver.gceutils.list_instances')
    def test_list_instances(self, mock_list_instances, mock_get_metadata):
        mock_list_instances.side_effect = gce_mock.list_instances
        mock_get_metadata.side_effect = gce_mock.get_instances_metadata_key
        instances_list = self._driver.list_instances()
        self.assertTrue(isinstance(instances_list, list))
        self.assertEqual(["instance-1", "instance-2"], instances_list)

    @mock.patch('nova.virt.gce.driver.gceutils.get_instances_metadata_key')
    @mock.patch('nova.virt.gce.driver.gceutils.list_instances')
    def test_list_instance_uuids(self, mock_list_instances, mock_get_metadata):
        mock_list_instances.side_effect = gce_mock.list_instances
        mock_get_metadata.side_effect = gce_mock.get_instances_metadata_key
        instances_list = self._driver.list_instance_uuids()
        self.assertTrue(isinstance(instances_list, list))
        self.assertEqual(2, len(instances_list))

    @mock.patch('nova.virt.gce.driver.gceutils.set_instance_metadata')
    @mock.patch('nova.virt.gce.driver.gceutils.get_instance')
    @mock.patch('nova.virt.gce.driver.gceutils.wait_for_operation')
    @mock.patch('nova.virt.gce.driver.gceutils.create_instance')
    @mock.patch('nova.virt.gce.driver.GCEDriver._process_network_info')
    def test_spawn_success(self, mock_process, mock_create, mock_wait,
                           mock_get, mock_set):
        network_interfaces = []
        mock_process.return_value = network_interfaces
        mock_create.side_effect = gce_mock.create_anything
        mock_wait.side_effect = gce_mock.wait_for_operation
        mock_get.side_effect = gce_mock.get_instance
        mock_set.side_effect = gce_mock.create_anything
        self.assertIsNone(
            self._driver.spawn(context=self.context, instance=self.instance,
                               image_meta={}, injected_files=None,
                               admin_password=None))
        instance_link = self.instance.system_metadata['image_gce_link']
        flavor_link = "zones/%s/machineTypes/%s" % (self._driver.gce_zone,
                                                    self.instance.flavor.name)
        gce_instance_name = 'inst-' + self.instance.uuid
        mock_create.assert_called_once_with(
            self._driver.gce_svc, self._driver.gce_project,
            self._driver.gce_zone, gce_instance_name, instance_link,
            flavor_link, network_interfaces)
        mock_get.assert_called_with(
            self._driver.gce_svc, self._driver.gce_project,
            self._driver.gce_zone, gce_instance_name)

    @mock.patch('nova.virt.gce.driver.gceutils.set_instance_metadata')
    @mock.patch('nova.virt.gce.driver.gceutils.get_instance')
    @mock.patch('nova.virt.gce.driver.gceutils.wait_for_operation')
    @mock.patch('nova.virt.gce.driver.gceutils.create_instance')
    def test_spawn_without_network(self, mock_create, mock_wait, mock_get,
                                   mock_set):
        mock_create.side_effect = gce_mock.create_anything
        mock_wait.side_effect = gce_mock.wait_for_operation
        mock_get.side_effect = gce_mock.get_instance
        mock_set.side_effect = gce_mock.create_anything
        self.assertRaises(exception.BuildAbortException, self._driver.spawn,
                          context=self.context, instance=self.instance,
                          image_meta={}, injected_files=None,
                          admin_password=None)

    @mock.patch('nova.virt.gce.driver.gceutils.wait_for_operation')
    @mock.patch('nova.virt.gce.driver.gceutils.stop_instance')
    def test_power_off(self, mock_stop, mock_wait):
        mock_stop.side_effect = gce_mock.create_anything
        mock_wait.side_effect = gce_mock.wait_for_operation
        self._driver.power_off(instance=self.instance)
        mock_wait.assert_called_once_with(self._driver.gce_svc,
                                          self._driver.gce_project,
                                          gce_mock.fake_operation())

    @mock.patch('nova.virt.gce.driver.gceutils.wait_for_operation')
    @mock.patch('nova.virt.gce.driver.gceutils.start_instance')
    def test_power_on(self, mock_start, mock_wait):
        mock_start.side_effect = gce_mock.create_anything
        mock_wait.side_effect = gce_mock.wait_for_operation
        self._driver.power_on(context=self.context, instance=self.instance,
                              network_info=[], block_device_info=None)
        mock_wait.assert_called_once_with(self._driver.gce_svc,
                                          self._driver.gce_project,
                                          gce_mock.fake_operation())

    @mock.patch('nova.virt.gce.driver.gceutils.wait_for_operation')
    @mock.patch('nova.virt.gce.driver.gceutils.delete_instance')
    def test_destroy(self, mock_destroy, mock_wait):
        mock_destroy.side_effect = gce_mock.create_anything
        mock_wait.side_effect = gce_mock.wait_for_operation
        self._driver.destroy(context=self.context, instance=self.instance,
                             network_info=[])
        mock_wait.assert_called_once_with(self._driver.gce_svc,
                                          self._driver.gce_project,
                                          gce_mock.fake_operation(),
                                          interval=5,
                                          timeout=300)

    @mock.patch('nova.virt.gce.driver.gceutils.wait_for_operation')
    @mock.patch('nova.virt.gce.driver.gceutils.attach_disk')
    def test_attach_volume(self, mock_attach, mock_wait):
        mock_attach.side_effect = gce_mock.create_anything
        mock_wait.side_effect = gce_mock.wait_for_operation
        disk_data = gce_mock.get_disk(self._driver.gce_svc,
                                      self._driver.gce_project,
                                      self._driver.gce_zone, "instance-1")
        self._driver.attach_volume(context=self.context, connection_info=dict(
            data=disk_data), instance=self.instance, mountpoint="/dev/sda")
        mock_attach.assert_called_once_with(
            self._driver.gce_svc, self._driver.gce_project,
            self._driver.gce_zone, self.instance.metadata['gce_id'],
            disk_data['name'], disk_data['selfLink'])
        mock_wait.assert_called_once_with(self._driver.gce_svc,
                                          self._driver.gce_project,
                                          gce_mock.fake_operation())

    @mock.patch('nova.virt.gce.driver.gceutils.wait_for_operation')
    @mock.patch('nova.virt.gce.driver.gceutils.detach_disk')
    def test_detach_volume(self, mock_detach, mock_wait):
        mock_detach.side_effect = gce_mock.create_anything
        mock_wait.side_effect = gce_mock.wait_for_operation
        disk_data = gce_mock.get_disk(self._driver.gce_svc,
                                      self._driver.gce_project,
                                      self._driver.gce_zone, "instance-1")
        self._driver.detach_volume(connection_info=dict(
            data=disk_data), instance=self.instance, mountpoint="/dev/sda")
        mock_detach.assert_called_once_with(
            self._driver.gce_svc, self._driver.gce_project,
            self._driver.gce_zone, self.instance.metadata['gce_id'],
            disk_data['name'])
        mock_wait.assert_called_once_with(self._driver.gce_svc,
                                          self._driver.gce_project,
                                          gce_mock.fake_operation())

    @mock.patch('nova.virt.gce.driver.gceutils.get_instance')
    def test_snapshot_without_boot(self, mock_get_instance):
        mock_get_instance.side_effect = gce_mock.get_instance_without_boot
        self.assertRaises(exception.InvalidMetadata, self._driver.snapshot,
                          context=self.context, instance=self.instance,
                          image_id=None,
                          update_task_state=gce_mock.update_task_state)
        mock_get_instance.assert_called_once_with(
            self._driver.gce_svc, self._driver.gce_project,
            self._driver.gce_zone, self.instance.metadata['gce_id'])

    @mock.patch('nova.virt.gce.driver.gceutils.delete_snapshot')
    @mock.patch('nova.virt.gce.driver.gceutils.delete_disk')
    @mock.patch('nova.virt.gce.driver.gceutils.get_image')
    @mock.patch('nova.virt.gce.driver.gceutils.create_image_from_disk')
    @mock.patch('nova.virt.gce.driver.gceutils.create_disk_from_snapshot')
    @mock.patch('nova.virt.gce.driver.gceutils.start_instance')
    @mock.patch('nova.virt.gce.driver.gceutils.snapshot_disk')
    @mock.patch('nova.image.glance.get_default_image_service')
    @mock.patch('nova.virt.gce.driver.gceutils.get_disk')
    @mock.patch('nova.virt.gce.driver.gceutils.wait_for_operation')
    @mock.patch('nova.virt.gce.driver.gceutils.stop_instance')
    @mock.patch('nova.virt.gce.driver.gceutils.get_instance')
    def test_snapshot_success(self, mock_get_instance, mock_stop, mock_wait,
                              mock_get_disk, mock_glance, mock_snapshot_disk,
                              mock_start, mock_create_disk, mock_create_image,
                              mock_get_image, mock_delete_image,
                              mock_delete_snapshot):
        image_id = "fake_image"
        snapshot_link = "projects/omni-163105/zones/us-central1-c/disks/"
        mock_get_instance.side_effect = gce_mock.get_instance
        mock_stop.side_effect = gce_mock.create_anything
        mock_wait.side_effect = gce_mock.wait_for_operation
        mock_get_disk.side_effect = gce_mock.get_disk
        mock_glance.side_effect = FakeImageService
        mock_snapshot_disk.side_effect = gce_mock.create_anything
        mock_start.side_effect = gce_mock.create_anything
        mock_create_disk.side_effect = gce_mock.create_anything
        mock_create_image.side_effect = gce_mock.create_anything
        mock_get_image.side_effect = gce_mock.get_image
        mock_delete_image.side_effect = gce_mock.delete_anything
        mock_delete_snapshot.side_effect = gce_mock.delete_anything
        self.assertIsNone(
            self._driver.snapshot(
                context=self.context, instance=self.instance,
                image_id=image_id,
                update_task_state=gce_mock.update_task_state))
        mock_create_image.assert_called_once_with(self._driver.gce_svc,
                                                  self._driver.gce_project,
                                                  image_id,
                                                  snapshot_link + image_id)
