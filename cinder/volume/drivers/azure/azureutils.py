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

from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.compute.models import DiskCreateOption
from azure.mgmt.resource import ResourceManagementClient
from cinder import exception
from functools import partial
from oslo_log import log as logging

import six

LOG = logging.getLogger(__name__)


def _get_credentials(tenant_id, client_id, client_secret):
    credentials = ServicePrincipalCredentials(
        client_id=client_id, secret=client_secret, tenant=tenant_id)
    return credentials


def get_azure_client(tenant_id, client_id, client_secret, subscription_id,
                     cls=None):
    """Returns Azure compute resource object for interacting with Azure API

    :param tenant_id: string, tenant_id from azure account
    :param client_id: string, client_id (application id)
    :param client_secret: string, secret key of application
    :param subscription_id: string, unique identification id of account
    :return: :class:`Resource <Resource>` object
    """
    credentials = _get_credentials(tenant_id, client_id, client_secret)
    client = cls(credentials, subscription_id)
    return client

get_management_client = partial(get_azure_client, cls=ComputeManagementClient)
get_resource_client = partial(get_azure_client, cls=ResourceManagementClient)


def check_resource_existence(client, resource_group):
    """Create if resource group exists in Azure or not

    :param client: Azure object using ResourceManagementClient
    :param resource_group: string, name of Azure resource group
    :return: True if exists, otherwise False
    :rtype: boolean
    """
    response = client.resource_groups.check_existence(resource_group)
    return response


def get_disk(client, resource_group, disk_name):
    """Get disk info from Azure

    :param client: Azure object using ComputeManagementClient
    :param resource_group: string, name of Azure resource group
    :param disk_name: string, name of disk
    :return: class:`Resource <Resource>` object
    :rtype:
    class 'azure.mgmt.compute.compute.v2016_04_30_preview.models.disk.Disk'
    """
    return client.disks.get(resource_group, disk_name)


def get_snapshot(client, resource_group, snapshot_name):
    """Get snapshot info from Azure

    :param client: Azure object using ComputeManagementClient
    :param resource_group: string, name of Azure resource group
    :param snapshot_name: string, name of snapshot
    :return: class:`Resource <Resource>` object
    :rtype: class
    `azure.mgmt.compute.compute.v2016_04_30_preview.models.snapshot.Snapshot`
    """
    return client.snapshots.get(resource_group, snapshot_name)


def get_image(client, resource_group, image_name):
    return client.images.get(resource_group, image_name)


def create_resource_group(client, resource_group, region):
    """Create resource group in Azure

    :param client: Azure object using ResourceManagementClient
    :param resource_group: string, name of Azure resource group
    :param region: string, name of Azure region
    """
    response = client.resource_groups.create_or_update(
        resource_group, {'location': region})
    LOG.debug("resource_group response: {0}".format(response))
    LOG.debug("Created Resource Group '{0}' in Azure".format(resource_group))


def create_disk(client, resource_group, region, disk_name, size):
    """Create disk in Azure

    :param client: Azure object using ComputeManagementClient
    :param resource_group: string, name of Azure resource group
    :param region: string, name of Azure region
    :param disk_name: string, name of disk
    :param size: int, size of disk in Gb
    """
    data = {
        'location': region,
        'disk_size_gb': size,
        'creation_data': {
            'create_option': DiskCreateOption.empty
        }
    }
    try:
        async_action = client.disks.create_or_update(
            resource_group, disk_name, data)
        LOG.debug("create_disk response: {0}".format(async_action.result()))
        LOG.debug('Created Disk: %s in Azure.' % disk_name)
    except Exception as e:
        message = "Create disk {0} in Azure failed. reason: {1}".format(
            disk_name, six.text_type(e))
        LOG.exception(message)
        raise exception.VolumeBackendAPIException(data=message)


def create_disk_from_snapshot(client, resource_group, region, disk_name,
                              snapshot_name):
    """Create disk from snapshot in Azure

    :param client: Azure object using ComputeManagementClient
    :param resource_group: string, name of Azure resource group
    :param region: string, name of Azure region
    :param disk_name: string, name of disk
    :param snapshot_name: string, name of snapshot
    """
    try:
        snapshot_info = get_snapshot(client, resource_group, snapshot_name)
        data = {
            'location': region,
            'creation_data': {
                'create_option': DiskCreateOption.copy,
                'source_resource_id': snapshot_info.id
            }
        }
        async_action = client.disks.create_or_update(
            resource_group, disk_name, data)
        LOG.debug("create_disk_from_snapshot response: {0}".format(
            async_action.result()))
        LOG.debug("Created %s volume from %s snapshot" % (disk_name,
                                                          snapshot_name))
    except Exception as e:
        message = "Create Volume from Snapshot {0} failed. reason: {1}"
        message = message.format(snapshot_name, six.text_type(e))
        LOG.exception(message)
        raise exception.VolumeBackendAPIException(data=message)


def create_disk_from_disk(client, resource_group, region,
                          src_vol, dest_vol):
    """Create disk from disk in Azure

    :param client: Azure object using ComputeManagementClient
    :param resource_group: string, name of Azure resource group
    :param region: string, name of Azure region
    :param src_vol: class:`cinder.objects.volume.Volume`, Source volume data
    :param dest_vol: class:`cinder.objects.volume.Volume`, data for volume to
                     be created
    """
    src_disk_details = get_disk(client, resource_group, 'vol-' + src_vol.id)
    data = {
        'location': region,
        'creation_data': {
            'create_option': DiskCreateOption.copy,
            'source_resource_id': src_disk_details.id
        }
    }
    try:
        async_action = client.disks.create_or_update(
            resource_group, 'vol-' + dest_vol.id, data)
        LOG.debug('create_disk_from_disk response: {0}'.format(
            async_action.result()))
        LOG.debug('Created Disk: {0} in Azure.'.format('vol-' + dest_vol.id))
    except Exception as e:
        message = "Create disk {0} in Azure failed. reason: {1}".format(
            'vol-' + dest_vol['id'], six.text_type(e))
        LOG.exception(message)
        raise exception.VolumeBackendAPIException(data=message)


def create_disk_from_image(client, resource_group, region, image_meta, volume):
    """Create disk from image in Azure

    :param client: Azure object using ComputeManagementClient
    :param resource_group: string, name of Azure resource group
    :param region: string, name of Azure region
    :param image_meta: dict, image metadata
    :param volume: class:`cinder.objects.volume.Volume`, volume data
    """
    resp = get_image(client, resource_group, image_meta['name'])
    volume_name = 'vol-' + volume.id
    data = {
        'location': region,
        'disk_size_gb': volume.size,
        'creation_data': {
            'create_option': DiskCreateOption.copy,
            'source_resource_id': resp.storage_profile.os_disk.managed_disk.id
        }
    }
    try:
        async_action = client.disks.create_or_update(
            resource_group, volume_name, data)
        result = async_action.result()
        LOG.debug('create_disk_from_image response: {0}'.format(result))
        LOG.debug('Created Disk: {0} in Azure.'.format(volume_name))
        return result
    except Exception as e:
        message = "Create disk {0} in Azure failed. reason: {1}".format(
            volume_name, six.text_type(e))
        LOG.exception(message)
        raise exception.VolumeBackendAPIException(data=message)


def delete_disk(client, resource_group, disk_name):
    """Delete disk in Azure

    :param client: Azure object using ComputeManagementClient
    :param resource_group: string, name of Azure resource group
    :param disk_name: string, name of disk
    """
    try:
        # checking if disk is available or not. If not available, then
        # get_disk() raises Exception
        _ = get_disk(client, resource_group, disk_name)  # noqa
        async_action = client.disks.delete(resource_group, disk_name)
        LOG.debug("delete_disk response: {0}".format(async_action.result()))
        LOG.debug('Deleted Disk: %s from Azure.' % disk_name)
    except Exception as e:
        message = "Delete Disk {0} in Azure failed. reason: {1}".format(
            disk_name, six.text_type(e))
        LOG.exception(message)
        raise exception.VolumeBackendAPIException(data=message)


def snapshot_disk(client, resource_group, region, disk_name,
                  snapshot_name):
    """Create snapshot of disk in Azure

    :param client: Azure object using ComputeManagementClient
    :param resource_group: string, name of Azure resource group
    :param region: string, name of Azure region
    :param disk_name: string, name of disk
    :param snapshot_name: string, name of snapshot
    """
    try:
        disk_info = get_disk(client, resource_group, disk_name)
        data = {
            'location': region,
            'creation_data': {
                'create_option': DiskCreateOption.copy,
                'source_uri': disk_info.id
            }
        }
        async_action = client.snapshots.create_or_update(
            resource_group, snapshot_name, data)
        LOG.debug("snapshot_disk response: {0}".format(async_action.result()))
        LOG.debug('Created Snapshot: %s in Azure.' % snapshot_name)
    except Exception as e:
        message = "Create Snapshot {0} in Azure failed. reason: {1}".format(
            snapshot_name, six.text_type(e))
        LOG.exception(message)
        raise exception.VolumeBackendAPIException(data=message)


def delete_snapshot(client, resource_group, snapshot_name):
    """Delete snapshot in Azure

    :param client: Azure object using ComputeManagementClient
    :param resource_group: string, name of Azure resource group
    :param snapshot_name: string, name of snapshot
    """
    try:
        # checking if snapshot is available or not. If not available, then
        # get_snapshot() raises Exception
        _ = get_snapshot(client, resource_group, snapshot_name)  # noqa
        async_action = client.snapshots.delete(resource_group,
                                               snapshot_name)
        LOG.debug("delete_snapshot response: {0}".format(
            async_action.result()))
        LOG.debug('Deleted Snapshot: %s from Azure.' % snapshot_name)
    except Exception as e:
        message = "Delete Snapshot {0} from Azure failed. reason: {1}"
        message = message.format(snapshot_name, six.text_type(e))
        LOG.exception(message)
        raise exception.VolumeBackendAPIException(data=message)
