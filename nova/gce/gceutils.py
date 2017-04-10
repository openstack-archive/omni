# Copyright (c) 2017 Platform9 Systems Inc.
# All Rights reserved
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

import six
import time
from oslo_log import log as logging

from googleapiclient.discovery import build
from oauth2client.client import GoogleCredentials

LOG = logging.getLogger(__name__)


def list_instances(compute, project, zone):
    result = compute.instances().list(project=project, zone=zone).execute()
    return result['items']


def get_instance(compute, project, zone, instance):
    result = compute.instances().get(
        project=project, zone=zone, instance=instance).execute()
    return result


def get_instance_metadata(compute, project, zone, instance):
    if isinstance(instance, six.string_types):
        instance = get_instance(compute, project, zone, instance)
    return instance['metadata']


def get_instances_metadata_key(compute, project, zone, instance, key):
    metadata = get_instance_metadata(compute, project, zone, instance)
    if 'items' in metadata:
        for item in metadata['items']:
            if item['key'] == key:
                return item['value']
    return None


def get_external_ip(compute, project, zone, instance):
    """ Return external IP of instance return empty string otherwise """
    if isinstance(instance, six.string_types):
        instance = get_instance(compute, project, zone, instance)
    for interface in instance.get('networkInterfaces', []):
        for config in interface.get('accessConfigs', []):
            if config['type'] == 'ONE_TO_ONE_NAT' and 'natIP' in config:
                return config['natIP']
    return ''


def set_instance_metadata(compute,
                          project,
                          zone,
                          instance,
                          items,
                          operation='add'):
    assert (isinstance(items, list))
    metadata = get_instance_metadata(compute, project, zone, instance)
    if operation == 'add':
        if 'items' in metadata:
            metadata['items'].extend(items)
        else:
            metadata['items'] = items
    LOG.info("Adding metadata %s" % (metadata, ))
    # TODO: Add del operation if required
    return compute.instances().setMetadata(
        project=project, zone=zone, instance=instance,
        body=metadata).execute()


def create_instance(compute, project, zone, name):
    source_disk_image = "projects/%s/global/images/%s" % (
        "debian-cloud", "debian-8-jessie-v20170327")
    machine_type = "zones/%s/machineTypes/n1-standard-1" % zone

    config = {
        'kind':
        'compute#instance',
        'name':
        name,
        'machineType':
        machine_type,

        # Specify the boot disk and the image to use as a source.
        'disks': [{
            'boot': True,
            'autoDelete': True,
            'initializeParams': {
                'sourceImage': source_disk_image,
            }
        }],

        # Specify a network interface with NAT to access the public
        # internet.
        'networkInterfaces': [{
            'network':
            'global/networks/default',
            'accessConfigs': [{
                'type': 'ONE_TO_ONE_NAT',
                'name': 'External NAT'
            }]
        }],

        # Allow the instance to access cloud storage and logging.
        'serviceAccounts': [{
            'email':
            'default',
            'scopes': [
                'https://www.googleapis.com/auth/devstorage.full_control',
                'https://www.googleapis.com/auth/logging.write',
                'https://www.googleapis.com/auth/compute'
            ]
        }],
    }

    return compute.instances().insert(
        project=project, zone=zone, body=config).execute()


def delete_instance(compute, project, zone, name):
    return compute.instances().delete(
        project=project, zone=zone, instance=name).execute()


def stop_instance(compute, project, zone, name):
    return compute.instances().stop(
        project=project, zone=zone, instance=name).execute()


def start_instance(compute, project, zone, name):
    return compute.instances().start(
        project=project, zone=zone, instance=name).execute()


def reset_instance(compute, project, zone, name):
    """ Performs a hard reset on the instance """
    return compute.instances().reset(
        project=project, zone=zone, instance=name).execute()


def wait_for_operation(compute, project, zone, operation):
    operation_name = operation['name']
    while True:
        result = compute.zoneOperations().get(
            project=project, zone=zone, operation=operation_name).execute()
        if result['status'] == 'DONE':
            LOG.info("Operation %s status is %s" % (operation_name,
                                                    result['status']))
            if 'error' in result:
                raise Exception(result['error'])
            return result
        else:
            # TODO: Use event loop instead
            time.sleep(1)


def get_gce_service(service_key):
    credentials = GoogleCredentials.from_stream(service_key)
    service = build('compute', 'v1', credentials=credentials)
    return service


def get_machines_info(compute, project, zone):
    response = compute.machineTypes().list(
        project=project, zone=zone).execute()
    GCE_MAP = {
        machine_type['name']: {
            'memory_mb': machine_type['memoryMb'],
            'vcpus': machine_type['guestCpus']
        }
        for machine_type in response['items']
    }
    return GCE_MAP
