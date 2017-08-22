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

from msrestazure.azure_exceptions import CloudError
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


def _get_client(tenant_id, client_id, client_secret, subscription_id,
                cls=None):
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


def _perform_and_wait(operation, args=(), kwargs={}, timeout=300):
    operation(*args, **kwargs).wait(timeout=timeout)


def get_vm_sizes(compute, region):
    vmsize_dict = {}
    for i in compute.virtual_machine_sizes.list(location=region):
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
    return compute.virtual_machines.get(
        resource_group, instance_name, expand='instanceView')


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


def get_subnet(network, resource_group, network_name, name):
    try:
        return network.subnets.get(resource_group, network_name, name)
    except CloudError:
        # TODO(ssudake21): Raise specific exception
        raise CloudError


def create_nic(network, resource_group, name, body):
    async_nic_creation = network.network_interfaces.create_or_update(
        resource_group, name, body)
    return async_nic_creation.result()


def create_or_update_instance(compute, resource_group, name, body):
    _perform_and_wait(compute.virtual_machines.create_or_update,
                      (resource_group, name, body))
