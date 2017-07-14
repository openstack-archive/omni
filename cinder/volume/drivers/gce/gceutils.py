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

from googleapiclient.discovery import build
from oauth2client.client import GoogleCredentials
from oslo_log import log as logging

from cinder.i18n import _
from oslo_service import loopingcall
from oslo_utils import reflection

LOG = logging.getLogger(__name__)


class GceOperationError(Exception):
    pass


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
            LOG.info("Operation %s status is %s" % (name, result['status']))
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


def create_disk_from_snapshot(compute, project, zone, name, snapshot_name):
    """Create disk from snapshot in GCE
    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param zone: string, GCE Name of zone
    :param name: string, GCE disk name
    :param snapshot_name: string, GCE snapshot name
    :return: Operation information
    :rtype: dict
    """
    gce_snapshot = get_snapshot(compute, project, snapshot_name)
    body = {
        "name": name,
        "zone": "projects/%s/zones/%s" % (project, zone),
        "type": "projects/%s/zones/%s/diskTypes/pd-standard" % (project, zone),
        "sourceSnapshot": gce_snapshot["selfLink"],
        "sizeGb": gce_snapshot["diskSizeGb"]
    }
    return compute.disks().insert(project=project, zone=zone, body=body,
                                  sourceImage=None).execute()
