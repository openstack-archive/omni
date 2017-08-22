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

from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient
from functools import partial
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


def get_credentials(tenant_id, client_id, client_secret):
    credentials = ServicePrincipalCredentials(
        client_id=client_id, secret=client_secret, tenant=tenant_id)
    return credentials


def _get_client(tenant_id, client_id, client_secret, subscription_id, cls=None):
    """Returns Azure compute resource object for interacting with Azure API

    :param tenant_id: string, tenant_id from azure account
    :param client_id: string, client_id (application id)
    :param client_secret: string, secret key of application
    :param subscription_id: string, unique identification id of account
    :return: :class:`Resource <Resource>` object
    """
    credentials = get_credentials(tenant_id, client_id, client_secret)
    client = cls(credentials, subscription_id)
    return client


get_compute_client = partial(_get_client, cls=ComputeManagementClient)
get_resource_client = partial(_get_client, cls=ResourceManagementClient)
get_network_client = partial(_get_client, cls=NetworkManagementClient)


def get_vm_sizes(compute, zone):
    vmsize_dict = {}
    for i in compute.virtual_machine_sizes.list(location=zone):
        vmsize_dict[i.name] = i
    return vmsize_dict


def list_instances(compute, resource_group):
    """Returns list of Azure instance resources for specified resource_group

    :param compute: Azure object using ComputeManagementClient
    :param resource_group: string, name of Azure resource group
    :return: list of Azure VMs in resource_group
    :rtype: list
    """
    return compute.virtual_machines.list(resource_group)


def get_instance(compute, resource_group, instance_name):
    """Get Azure instance information

    :param compute: Azure object using ComputeManagementClient
    :param resource_group: string, name of Azure resource group
    :param instance_name: string, name of Azure instance
    """
    return compute.virtual_machines.get(resource_group, instance_name)


def get_external_ip(compute, network_client, resource_group, instance_name):
    """Get public IP of Azure VM

    :param compute: Azure object using ComputeManagementClient
    :param network_client: Azure object using NetworkManagementClient
    :param resource_group: string, name of Azure resource group
    :param instance_name: string, name of Azure instance
    """
    instance_info = get_instance(compute, resource_group, instance_name)
    interface_full_id = instance_info.network_profile.network_interfaces[0].id
    interface_name = interface_full_id.split('/')[-1]
    interface_details = network_client.network_interfaces.get(
        resource_group, interface_name)

    ip_reference = interface_details.ip_configurations[0].public_ip_address
    ip_reference = ip_reference.id.split("/")
    ip_name = ip_reference[8]
    ip_group = ip_reference[4]

    public_ip = network_client.public_ip_addresses.get(ip_group, ip_name)
    public_ip = public_ip.ip_address
    return public_ip


def create_instance():
    """Create GCE instance

    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param zone: string, GCE Name of zone
    :param name: string, Name of instance to be launched
    :param image_link: url, GCE Image link for instance launch
    :param machine_link: url, GCE Machine link for instance launch
    """
    pass


def delete_instance(compute, project, zone, name):
    """Delete GCE instance

    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param zone: string, GCE Name of zone
    :param name: string, Name of the GCE instance
    """
    pass


def stop_instance(compute, project, zone, name):
    """Stop GCE instance

    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param zone: string, GCE Name of zone
    :param name: string, Name of the GCE instance
    """
    pass


def start_instance(compute, project, zone, name):
    """Start GCE instance

    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param zone: string, GCE Name of zone
    :param name: string, Name of the GCE instance
    """
    pass


def reset_instance(compute, project, zone, name):
    """Hard reset GCE instance

    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param zone: string, GCE Name of zone
    :param name: string, Name of the GCE instance
    """
    pass


def get_images(compute, project):
    """Return public images info from GCE

    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    """
    pass


def get_image(compute, project, name):
    """Return public images info from GCE

    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    """
    pass


def delete_image(compute, project, name):
    """Delete image from GCE

    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param name: string, GCE image name
    :return: Operation information
    :rtype: dict
    """
    pass


def get_network(compute, project, name):
    """Return network info

    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param name: string, GCE network name
    """
    pass


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
    pass


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
    pass


def get_instance_boot_disk(compute, project, zone, instance):
    """Return boot disk info for instance
    call get_instance
    if disk['boot'], call get_disk and return disk_info
    else raise AssertionError("Boot disk not found for instance %s" % instance)
    """
    pass


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
    pass


def delete_disk(compute, project, zone, name):
    """Delete disk in GCE

    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param zone: string, GCE Name of zone
    :param name: string, GCE disk name
    :return: Operation information
    :rtype: dict
    """
    pass


def get_disk(compute, project, zone, name):
    """Get info of disk in GCE

    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param zone: string, GCE Name of zone
    :param name: string, GCE disk name
    :return: GCE disk information
    :rtype: dict
    """
    pass


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
    pass


def get_snapshot(compute, project, name):
    """Get info of snapshot in GCE

    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param name: string, GCE snapshot name
    :return: GCE snapshot information
    :rtype: dict
    """
    pass


def delete_snapshot(compute, project, name):
    """Delete snapshot in GCE

    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    :param name: string, GCE snapshot name
    :return: Operation information
    :rtype: dict
    """
    pass


def create_disk_from_snapshot(compute,
                              project,
                              zone,
                              name,
                              snapshot_name,
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
    pass


def create_image_from_disk(compute, project, name, disk_link):
    pass
