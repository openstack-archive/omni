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

import time
import six
from oslo_log import log as logging

from nova.i18n import _LI, _
from googleapiclient.discovery import build
from oauth2client.client import GoogleCredentials
from oslo_service import loopingcall
from oslo_utils import reflection
from six.moves import urllib

LOG = logging.getLogger(__name__)


class _FixedIntervalWithTimeoutLoopingCall(loopingcall.LoopingCallBase):
    """A fixed interval looping call with timeout checking mechanism."""

    _RUN_ONLY_ONE_MESSAGE = _("A fixed interval looping call with timeout"
                              " checking and can only run one function at"
                              " at a time")

    _KIND = _('Fixed interval looping call with timeout checking.')

    def start(self, interval, initial_delay=None, stop_on_exception=True,
              timeout=0):
        start_time = time.time()

        def _idle_for(result, elapsed):
            delay = round(elapsed - interval, 2)
            if delay > 0:
                func_name = reflection.get_callable_name(self.f)
                LOG.warning('Function %(func_name)r run outlasted '
                            'interval by %(delay).2f sec',
                            {'func_name': func_name,
                             'delay': delay})
            elapsed_time = time.time() - start_time
            if timeout > 0 and elapsed_time > timeout:
                raise loopingcall.LoopingCallTimeOut(
                    _('Looping call timed out after %.02f seconds') %
                    elapsed_time)
            return -delay if delay < 0 else 0

        return self._start(_idle_for, initial_delay=initial_delay,
                           stop_on_exception=stop_on_exception)


# Currently, default oslo.service version(newton) is 1.16.0.
# Once we upgrade oslo.service >= 1.19.0, we can remove temporary
# definition _FixedIntervalWithTimeoutLoopingCall
if not hasattr(loopingcall, 'FixedIntervalWithTimeoutLoopingCall'):
    loopingcall.FixedIntervalWithTimeoutLoopingCall = \
            _FixedIntervalWithTimeoutLoopingCall


class GceOperationError(Exception):
    pass


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


def create_instance(compute, project, zone, name, image_link, machine_link,
                    network_interfaces):
    """Create GCE instance
    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param zone: string, GCE Name of zone
    :param name: string, Name of instance to be launched
    :param image_link: url, GCE Image link for instance launch
    :param machine_link: url, GCE Machine link for instance launch
    """
    LOG.info(
        _LI("Launching instance %s with image %s, machine %s and network %s") %
        (name, image_link, machine_link, network_interfaces))

    config = {
        'kind': 'compute#instance',
        'name': name,
        'machineType': machine_link,
        'networkInterfaces': network_interfaces,
        # Specify the boot disk and the image to use as a source.
        'disks': [{
            'boot': True,
            'autoDelete': True,
            'initializeParams': {
                'sourceImage': image_link,
            }
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
    }  # yapf:disable
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


def wait_for_operation(compute, project, operation, interval=1, timeout=60):
    """Wait for GCE operation to complete, raise error if operation failure
    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param operation: object, Operation resource obtained by calling GCE asynchronous API
        All GCE asynchronous API's return operation resource to followup there completion.
    :param interval: int, Time period(seconds) between two GCE operation checks
    :param timeout: int, Absoulte time period(seconds) to monitor GCE operation
    """

    def watch_operation(name, request):
        result = request.execute()
        if result['status'] == 'DONE':
            LOG.info(
                _LI("Operation %s status is %s") % (name, result['status']))
            if 'error' in result:
                raise GceOperationError(result['error'])
            raise loopingcall.LoopingCallDone()

    operation_name = operation['name']

    if 'zone' in operation:
        zone = operation['zone'].split('/')[-1]
        monitor_request = compute.zoneOperations().get(
            project=project, zone=zone, operation=operation_name)
    elif 'region' in operation:
        region = operation['region'].split('/')[-1]
        monitor_request = compute.regionOperations().get(
            project=project, region=region, operation=operation_name)
    else:
        monitor_request = compute.globalOperations().get(
            project=project, operation=operation_name)

    timer = loopingcall.FixedIntervalWithTimeoutLoopingCall(
        watch_operation, operation_name, monitor_request)
    timer.start(interval=interval, timeout=timeout).wait()


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


def delete_image(compute, project, name):
    """Delete image from GCE
    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param name: string, GCE image name
    :return: Operation information
    :rtype: dict
    """
    result = compute.images().get(project=project, image=name).execute()
    return result


def get_network(compute, project, name):
    """Return network info
    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param name: string, GCE network name
    """
    result = compute.networks().get(project=project, network=name).execute()
    return result


def attach_disk(compute, project, zone, instance_name, disk_name, disk_link):
    """Attach disk to instance
    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param zone: string, GCE Name of zone
    :param instance_name: string, GCE instance name
    :param disk_name: string, GCE disk name
    :param disk_link: url, GCE disk link
    :return: Operation information
    :rtype: dict
    """
    body = {
        "type": "PERSISTENT",
        "mode": "READ_WRITE",
        "source": disk_link,
        "deviceName": disk_name,
        "boot": False,
        "autoDelete": False,
        "interface": "SCSI"
    }
    return compute.instances().attachDisk(project=project, zone=zone,
                                          instance=instance_name,
                                          body=body).execute()


def detach_disk(compute, project, zone, instance_name, disk_name):
    """Detach disk from instance
    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param zone: string, GCE Name of zone
    :param instance_name: string, GCE instance name
    :param disk_name: string, GCE disk name
    :return: Operation information
    :rtype: dict
    """
    return compute.instances().detachDisk(project=project, zone=zone,
                                          instance=instance_name,
                                          deviceName=disk_name).execute()


def get_instance_boot_disk(compute, project, zone, instance):
    """Return boot disk info for instance
    """
    gce_instance = get_instance(compute, project, zone, instance)
    for disk in gce_instance['disks']:
        if disk['boot']:
            disk_url = disk['source']
            # Extracting disk details from disk URL,
            # Eg. projects/<project>/zones/<zone>/disks/<disk_name>
            items = urllib.parse.urlparse(disk_url).path.strip('/').split('/')
            if len(items) < 4 or items[-2] != 'disks':
                LOG.error(_LI('Invalid disk URL %s') % (disk_url))
            disk_name, zone = items[-1], items[-3]
            disk_info = get_disk(compute, project, zone, disk_name)
            return disk_info
    # We should never reach here
    raise AssertionError("Boot disk not found for instance %s" % instance)


def create_disk(compute, project, zone, name, size):
    """Create disk in GCE
    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param zone: string, GCE Name of zone
    :param name: string, GCE disk name
    :param size: int, size of disk inn Gb
    :return: Operation information
    :rtype: dict
    """
    body = {
        "name": name,
        "zone": "projects/%s/zones/%s" % (project, zone),
        "type": "projects/%s/zones/%s/diskTypes/pd-standard" % (project, zone),
        "sizeGb": size
    }
    return compute.disks().insert(project=project, zone=zone, body=body,
                                  sourceImage=None).execute()


def delete_disk(compute, project, zone, name):
    """Delete disk in GCE
    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param zone: string, GCE Name of zone
    :param name: string, GCE disk name
    :return: Operation information
    :rtype: dict
    """
    return compute.disks().delete(project=project, zone=zone,
                                  disk=name).execute()


def get_disk(compute, project, zone, name):
    """Get info of disk in GCE
    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param zone: string, GCE Name of zone
    :param name: string, GCE disk name
    :return: GCE disk information
    :rtype: dict
    """
    return compute.disks().get(project=project, zone=zone, disk=name).execute()


def snapshot_disk(compute, project, zone, name, snapshot_name):
    """Create snapshot of disk in GCE
    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param zone: string, GCE Name of zone
    :param name: string, GCE disk name
    :param snapshot_name: string, GCE snapshot name
    :return: Operation information
    :rtype: dict
    """
    body = {"name": snapshot_name}
    return compute.disks().createSnapshot(project=project, zone=zone,
                                          disk=name, body=body).execute()


def get_snapshot(compute, project, name):
    """Get info of snapshot in GCE
    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param name: string, GCE snapshot name
    :return: GCE snapshot information
    :rtype: dict
    """
    return compute.snapshots().get(project=project, snapshot=name).execute()


def delete_snapshot(compute, project, name):
    """Delete snapshot in GCE
    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param name: string, GCE snapshot name
    :return: Operation information
    :rtype: dict
    """
    return compute.snapshots().delete(project=project, snapshot=name).execute()


def create_disk_from_snapshot(compute, project, zone, name, snapshot_name,
                              disk_type="pd-standard"):
    """Create disk from snapshot in GCE
    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param zone: string, GCE Name of zone
    :param name: string, GCE disk name
    :param snapshot_name: string, GCE snapshot name
    :param disk_type: string, Disk type from (pd-standard, pd-sdd, local-ssd)
    :return: Operation information
    :rtype: dict
    """
    gce_snapshot = get_snapshot(compute, project, snapshot_name)
    body = {
        "name": name,
        "zone": "projects/%s/zones/%s" % (project, zone),
        "type": "projects/%s/zones/%s/diskTypes/%s" % (project, zone,
                                                       disk_type),
        "sourceSnapshot": gce_snapshot["selfLink"],
        "sizeGb": gce_snapshot["diskSizeGb"]
    }
    return compute.disks().insert(project=project, zone=zone, body=body,
                                  sourceImage=None).execute()


def create_image_from_disk(compute, project, name, disk_link):
    body = {"sourceDisk": disk_link, "name": name, "rawDisk": {}}
    return compute.images().insert(project=project, body=body).execute()
