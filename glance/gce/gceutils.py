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

import six
import time
from oslo_log import log as logging

from googleapiclient.discovery import build
from oauth2client.client import GoogleCredentials

LOG = logging.getLogger(__name__)


def list_instances(compute, project, zone):
    """Returns list of GCE instance resources for specified project
    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param zone: string, GCE Name of zone
    """
    result = compute.instances().list(project=project, zone=zone).execute()
    if 'items' not in result:
        return []
    return result['items']


def get_instance(compute, project, zone, instance):
    """Get GCE instance information
    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param zone: string, GCE Name of zone
    :param instance: string, Name of the GCE instance resource
    """
    result = compute.instances().get(project=project, zone=zone,
                                     instance=instance).execute()
    return result


def get_instance_metadata(compute, project, zone, instance):
    """Returns specified instance's metadata
    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param zone: string, GCE Name of zone
    :param instance: string or instance resource, Name of the GCE instance
        resource or GCE instance resource
    """
    if isinstance(instance, six.string_types):
        instance = get_instance(compute, project, zone, instance)
    return instance['metadata']


def get_instances_metadata_key(compute, project, zone, instance, key):
    """Returns particular key information for specified instance
    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param zone: string, GCE Name of zone
    :param instance: string or instance resource, Name of the GCE instance
        resource or GCE instance resource
    :param key: string, Key to retrieved from the instance metadata
    """
    metadata = get_instance_metadata(compute, project, zone, instance)
    if 'items' in metadata:
        for item in metadata['items']:
            if item['key'] == key:
                return item['value']
    return None


def get_external_ip(compute, project, zone, instance):
    """ Return external IP of GCE instance return empty string otherwise
    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param zone: string, GCE Name of zone
    :param instance: string or instance resource, Name of the GCE instance
        resource or GCE instance resource
    """
    if isinstance(instance, six.string_types):
        instance = get_instance(compute, project, zone, instance)
    for interface in instance.get('networkInterfaces', []):
        for config in interface.get('accessConfigs', []):
            if config['type'] == 'ONE_TO_ONE_NAT' and 'natIP' in config:
                return config['natIP']
    return ''


def set_instance_metadata(compute, project, zone, instance, items,
                          operation='add'):
    """Perform specified operation on GCE instance metadata
    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param zone: string, GCE Name of zone
    :param instance: string or instance resource, Name of the GCE instance
        resource or GCE instance resource
    :param items: list, List of items where each item is dictionary having
        'key' and 'value' as its members
        Refer following sample list,
        [ {'key': 'openstack_id', 'value': '1224555'}, ]
    :param operation: string, Operation to perform on instance metadata
    """
    if not isinstance(items, list):
        raise TypeError(
            "set_instance_metadata: items should be instance of list")
    metadata = get_instance_metadata(compute, project, zone, instance)
    if operation == 'add':
        if 'items' in metadata:
            metadata['items'].extend(items)
        else:
            metadata['items'] = items
    LOG.info("Adding metadata %s" % (metadata, ))
    # TODO: Add del operation if required
    return compute.instances().setMetadata(project=project, zone=zone,
                                           instance=instance,
                                           body=metadata).execute()


def create_instance(compute, project, zone, name, image_link, machine_link):
    """Create GCE instance
    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param zone: string, GCE Name of zone
    :param name: string, Name of instance to be launched
    :param image_link: url, GCE Image link for instance launch
    :param machine_link: url, GCE Machine link for instance launch
    """
    # source_disk_image = "projects/%s/global/images/%s" % (
    #     "debian-cloud", "debian-8-jessie-v20170327")
    # machine_link = "zones/%s/machineTypes/n1-standard-1" % zone
    LOG.info("Launching instance %s with image %s and machine %s" %
             (name, image_link, machine_link))

    config = {
        'kind':
        'compute#instance',
        'name':
        name,
        'machineType':
        machine_link,

        # Specify the boot disk and the image to use as a source.
        'disks': [{
            'boot': True,
            'autoDelete': True,
            'initializeParams': {
                'sourceImage': image_link,
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

    return compute.instances().insert(project=project, zone=zone,
                                      body=config).execute()


def delete_instance(compute, project, zone, name):
    """Delete GCE instance
    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param zone: string, GCE Name of zone
    :param name: string, Name of the GCE instance
    """
    return compute.instances().delete(project=project, zone=zone,
                                      instance=name).execute()


def stop_instance(compute, project, zone, name):
    """Stop GCE instance
    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param zone: string, GCE Name of zone
    :param name: string, Name of the GCE instance
    """
    return compute.instances().stop(project=project, zone=zone,
                                    instance=name).execute()


def start_instance(compute, project, zone, name):
    """Start GCE instance
    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param zone: string, GCE Name of zone
    :param name: string, Name of the GCE instance
    """
    return compute.instances().start(project=project, zone=zone,
                                     instance=name).execute()


def reset_instance(compute, project, zone, name):
    """Hard reset GCE instance
    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param zone: string, GCE Name of zone
    :param name: string, Name of the GCE instance
    """
    return compute.instances().reset(project=project, zone=zone,
                                     instance=name).execute()


def wait_for_operation(compute, project, zone, operation, interval=1,
                       timeout=60):
    """Wait for GCE operation to complete, raise error if operation failure
    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param zone: string, GCE Name of zone
    :param operation: object, Operation resource obtained by calling GCE API
    :param interval: int, Time period(seconds) between two GCE operation checks
    :param timeout: int, Absoulte time period(seconds) to monitor GCE operation
    """
    operation_name = operation['name']
    if interval < 1:
        raise ValueError("wait_for_operation: Interval should be positive")
    iterations = timeout / interval
    for i in range(iterations):
        result = compute.zoneOperations().get(
            project=project, zone=zone, operation=operation_name).execute()
        if result['status'] == 'DONE':
            LOG.info("Operation %s status is %s" % (operation_name,
                                                    result['status']))
            if 'error' in result:
                raise Exception(result['error'])
            return result
        time.sleep(interval)
    raise Exception(
        "wait_for_operation: Operation %s failed to perform in timeout %s" %
        (operation_name, timeout))


def get_gce_service(service_key):
    """Returns GCE compute resource object for interacting with GCE API
    :param service_key: string, Path of service key obtained from
        https://console.cloud.google.com/apis/credentials
    """
    credentials = GoogleCredentials.from_stream(service_key)
    service = build('compute', 'v1', credentials=credentials)
    return service


def get_machines_info(compute, project, zone):
    """Return machine type info from GCE
    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param zone: string, GCE Name of zone
    """
    response = compute.machineTypes().list(project=project,
                                           zone=zone).execute()
    GCE_MAP = {
        machine_type['name']: {
            'memory_mb': machine_type['memoryMb'],
            'vcpus': machine_type['guestCpus']
        }
        for machine_type in response['items']
    }
    return GCE_MAP


def get_images(compute, project):
    """Return public images info from GCE
    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    """
    response = compute.images().list(project=project,
                                     filter="status eq READY").execute()
    if 'items' not in response:
        return []
    imgs = filter(lambda img: 'deprecated' not in img, response['items'])
    return imgs


def get_image(compute, project, name):
    """Return public images info from GCE
    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    """
    result = compute.images().get(project=project, image=name).execute()
    return result
