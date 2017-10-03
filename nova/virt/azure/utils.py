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

from functools import partial

from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient
from msrestazure.azure_exceptions import CloudError
from oslo_log import log as logging

from nova import exception

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


def check_resource_existence(client, resource_group):
    """Create if resource group exists in Azure or not

    :param client: Azure object using ResourceManagementClient
    :param resource_group: string, name of Azure resource group
    :return: True if exists, otherwise False
    :rtype: boolean
    """
    response = client.resource_groups.check_existence(resource_group)
    return response


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


def azure_handle_exception(fn):
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            LOG.exception("Exception occurred in Azure operation: %s" %
                          (e.message))

    return wrapper


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


def get_nic(network, resource_group, name):
    try:
        return network.network_interfaces.get(resource_group, name)
    except CloudError:
        raise exception.PortNotFound(port_id=name)


def create_or_update_instance(compute, resource_group, name, body):
    _perform_and_wait(compute.virtual_machines.create_or_update,
                      (resource_group, name, body))


def delete_instance(compute, resource_group, name):
    _perform_and_wait(compute.virtual_machines.delete, (resource_group, name))


def restart_instance(compute, resource_group, name):
    _perform_and_wait(compute.virtual_machines.restart, (resource_group, name))


def start_instance(compute, resource_group, name):
    _perform_and_wait(compute.virtual_machines.start, (resource_group, name))


def stop_instance(compute, resource_group, name):
    _perform_and_wait(compute.virtual_machines.power_off, (resource_group,
                                                           name))


def get_image(compute, resource_group, name):
    return compute.images.get(resource_group, name)


@azure_handle_exception
def delete_disk(compute, resource_group, name):
    return compute.disks.delete(resource_group, name)
