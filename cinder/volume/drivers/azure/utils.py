"""
Copyright 2017 Platform9 Systems Inc.(http://www.platform9.com)
Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""

import six

from azure.common import AzureMissingResourceHttpError
from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.compute.models import DiskCreateOption
from cinder import exception
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


def get_azure_client(tenant_id, client_id, client_secret, subscription_id):
    """Returns Azure compute resource object for interacting with Azure API

    :param tenant_id: string, tenant_id from azure account
    :param client_id: string, client_id (application id)
    :param client_secret: string, secret key of application
    :param subscription_id: string, unique identification id of account
    :return: :class:`Resource <Resource>` object
    :rtype: ComputeManagementClient
    """
    credentials = ServicePrincipalCredentials(
        client_id=client_id, secret=client_secret, tenant=tenant_id)
    client = ComputeManagementClient(credentials, subscription_id)
    return client


def create_disk(compute, resource_group, zone, disk_name, size):
    """Create disk in Azure

    :param compute: Azure object using ComputeManagementClient
    :param zone: string, name of Azure zone
    :param disk_name: string, name of disk
    :param size: int, size of disk in Gb
    :return: Operation information
    :rtype: dict
    """
    data = {
        'location': zone,
        'disk_size_gb': size,
        'creation_data': {
            'create_option': DiskCreateOption.empty
        }
    }
    try:
        async_creation = compute.disks.create_or_update(
            resource_group, disk_name, data)
        LOG.info('Created Disk: %s in Azure.' % disk_name)
        return async_creation.result()
    except Exception as e:
        message = "Create disk {0} in Azure failed. reason: {1}".format(
            disk_name, six.text_type(e))
        LOG.exception(message)
        raise exception.VolumeBackendAPIException(data=message)


def delete_disk(compute, resource_group, disk_name):
    """Delete disk in Azure

    :param compute: Azure object using ComputeManagementClient
    :param disk_name: string, name of disk
    :return: Operation information
    :rtype: dict
    """
    try:
        async_deletion = compute.disks.delete(resource_group, disk_name)
        LOG.info('Deleted Disk: %s from Azure.' % disk_name)
        return async_deletion.result()
    except AzureMissingResourceHttpError:
        LOG.info("Disk: %s does not exist." % disk_name)
    except Exception as e:
        message = "Delete Disk {0} in Azure failed. reason: {1}".format(
            disk_name, six.text_type(e))
        LOG.exception(message)
        raise exception.VolumeBackendAPIException(data=message)


def get_disk(compute, resource_group, disk_name):
    """Get disk info from Azure

    :param compute: Azure object using ComputeManagementClient
    :param disk_name: string, name of disk
    :return: disk information
    :rtype:
    class 'azure.mgmt.compute.compute.v2016_04_30_preview.models.disk.Disk'
    """
    return compute.disks.get(resource_group, disk_name)


def snapshot_disk(compute, resource_group, zone, disk_name, snapshot_name):
    """Create snapshot of disk in Azure

    :param compute: Azure object using ComputeManagementClient
    :param zone: string, name of Azure zone
    :param disk_name: string, name of disk
    :param snapshot_name: string, name of snapshot
    :return: Operation information
    :rtype: dict
    """
    try:
        managed_disk = get_disk(compute, resource_group, disk_name)
        data = {
            'location': zone,
            'creation_data': {
                'create_option': DiskCreateOption.copy,
                'source_uri': managed_disk.id
            }
        }
        async_snapshot_creation = compute.snapshots.create_or_update(
            resource_group, snapshot_name, data)
        LOG.info('Created Snapshot: %s in Azure.' % snapshot_name)
        return async_snapshot_creation.result()
    except Exception as e:
        message = "Create Snapshot {0} in Azure failed. reason: {1}".format(
            snapshot_name, six.text_type(e))
        LOG.exception(message)
        raise exception.VolumeBackendAPIException(data=message)


def get_snapshot(compute, resource_group, snapshot_name):
    """Get snapshot info from Azure

    :param compute: Azure object using ComputeManagementClient
    :param snapshot_name: string, name of snapshot
    :return: snapshot information
    :rtype:
    azure.mgmt.compute.compute.v2016_04_30_preview.models.snapshot.Snapshot
    """
    return compute.snapshots.get(resource_group, snapshot_name)


def delete_snapshot(compute, resource_group, snapshot_name):
    """Delete snapshot in Azure

    :param compute: Azure object using ComputeManagementClient
    :param snapshot_name: string, name of snapshot
    :return: Operation information
    :rtype: dict
    """
    try:
        async_deletion = compute.snapshots.delete(resource_group,
                                                  snapshot_name)
        LOG.info('Deleted Snapshot: %s from Azure.' % snapshot_name)
        return async_deletion.result()
    except AzureMissingResourceHttpError:
        LOG.warning("snapshot: %s not found, skipping delete operations" %
                    snapshot_name)
        LOG.info('Successfully deleted snapshot: %s' % snapshot_name)
    except Exception as e:
        message = "Delete Snapshot {0} from Azure failed. reason: {1}"
        message = message.format(snapshot_name, six.text_type(e))
        LOG.exception(message)
        raise exception.VolumeBackendAPIException(data=message)


def create_disk_from_snapshot(compute, resource_group, zone, disk_name,
                              snapshot_name):
    """Create disk from snapshot in Azure

    :param compute: Azure object using ComputeManagementClient
    :param zone: string, name of Azure zone
    :param disk_name: string, name of disk
    :param snapshot_name: string, name of snapshot
    :return: Operation information
    :rtype: dict
    """
    try:
        snapshot_info = get_snapshot(compute, resource_group, snapshot_name)
        data = {
            'location': zone,
            'creation_data': {
                'create_option': DiskCreateOption.copy,
                'source_resource_id': snapshot_info.id
            }
        }
        async_creation = compute.disks.create_or_update(
            resource_group, disk_name, data)
        return async_creation.result()
    except Exception as e:
        message = "Create Volume from Snapshot {0} failed. reason: {1}"
        message = message.format(snapshot_name, six.text_type(e))
        LOG.exception(message)
        raise exception.VolumeBackendAPIException(data=message)
