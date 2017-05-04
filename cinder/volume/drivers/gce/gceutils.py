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

from googleapiclient.discovery import build
from oauth2client.client import GoogleCredentials
from oslo_log import log as logging

from cinder.i18n import _LI
from oslo_service import loopingcall

LOG = logging.getLogger(__name__)


class GceOperationError(Exception):
    pass


def list_instances(compute, project, zone):
    """Returns list of GCE instance resources for specified project
    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param zone: string, GCE Name of zone
    :return: Instances information
    :rtype: list
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
    :return: Instance information
    :rtype: dict
    """
    result = compute.instances().get(project=project, zone=zone,
                                     instance=instance).execute()
    return result


def wait_for_operation(compute, project, operation, interval=1, timeout=60):
    """Wait for GCE operation to complete, raise error if operation failure
    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param zone: string, GCE Name of zone
    :param operation: object, Operation resource obtained by calling GCE API
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
    :return: :class:`Resource <Resource>` object
    :rtype: googleapiclient.discovery.Resource
    """
    credentials = GoogleCredentials.from_stream(service_key)
    service = build('compute', 'v1', credentials=credentials)
    return service


def create_disk(compute, project, zone, name, size):
    body = {
        "name": name,
        "zone": "projects/%s/zones/%s" % (project, zone),
        "type": "projects/%s/zones/%s/diskTypes/pd-standard" % (project, zone),
        "sizeGb": size
    }
    return compute.disks().insert(project=project, zone=zone, body=body,
                                  sourceImage=None).execute()


def delete_disk(compute, project, zone, name):
    return compute.disks().delete(project=project, zone=zone,
                                  disk=name).execute()


def get_disk(compute, project, zone, name):
    return compute.disks().get(project=project, zone=zone, disk=name).execute()


def snapshot_disk(compute, project, zone, name, snapshot_name):
    body = {"name": snapshot_name}
    return compute.disks().createSnapshot(project=project, zone=zone,
                                          disk=name, body=body).execute()


def get_snashot(compute, project, name):
    return compute.snapshots().get(project=project, snapshot=name).execute()
