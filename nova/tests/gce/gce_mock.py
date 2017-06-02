# Copyright (c) 2017 Platform9 Systems Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import os
import six

from apiclient.http import HttpMock
from googleapiclient.discovery import build

DATA_DIR = os.path.dirname(os.path.abspath(__file__)) + '/data'


def fake_operation():
    return {'name': 'fake_operation'}


def get_gce_service(service_key):
    http = HttpMock(DATA_DIR + '/service/service_data.json', {'status': '200'})
    service = build('compute', 'v1', http=http, developerKey=service_key)
    return service


def list_instances(compute, project, zone):
    http = HttpMock(DATA_DIR + '/instance/list_instances.json',
                    {'status': '200'})
    request = compute.instances().list(project=project, zone=zone)
    response = request.execute(http=http)
    return response


def get_instance(compute, project, zone, instance):
    http = HttpMock(DATA_DIR + '/instance/get_instance.json',
                    {'status': '200'})
    request = compute.instances().get(project=project, zone=zone,
                                      instance=instance)
    response = request.execute(http=http)
    return response


def get_instance_without_boot(compute, project, zone, instance):
    http = HttpMock(DATA_DIR + '/instance/get_instance_without_boot.json',
                    {'status': '200'})
    request = compute.instances().get(project=project, zone=zone,
                                      instance=instance)
    response = request.execute(http=http)
    return response


def get_image(compute, project, name):
    http = HttpMock(DATA_DIR + '/image/get_image.json', {'status': '200'})
    request = compute.images().get(project=project, image=name)
    response = request.execute(http=http)
    return response


def get_instances_metadata_key(compute, project, zone, instance, key):
    if isinstance(instance, six.string_types):
        instance = get_instance(compute, project, zone, instance)
    metadata = instance['metadata']
    if 'items' in metadata:
        for item in metadata['items']:
            if item['key'] == key:
                return item['value']
    return None


def get_machines_info(compute, project, zone):
    http = HttpMock(DATA_DIR + '/machines_info/list_machines_info.json',
                    {'status': '200'})
    request = compute.machineTypes().list(project=project, zone=zone)
    response = request.execute(http=http)
    GCE_MAP = {
        machine_type['name']: {
            'memory_mb': machine_type['memoryMb'],
            'vcpus': machine_type['guestCpus']
        }
        for machine_type in response
    }
    return GCE_MAP


def get_disk(compute, project, zone, name):
    http = HttpMock(DATA_DIR + '/disk/get_disk.json', {'status': '200'})
    request = compute.disks().get(project=project, zone=zone, disk=name)
    response = request.execute(http=http)
    return response


def create_anything(*args, **kwargs):
    return fake_operation()


def wait_for_operation(*args, **kwargs):
    pass


def delete_anything(*args, **kwargs):
    return fake_operation()


def update_task_state(*args, **kwargs):
    pass


class FakeImageService(object):
    def show(self, context, image_id):
        return {'name': 'fake_image'}

    def update(self, context, image_id, image_metadata):
        pass
