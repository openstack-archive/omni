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
from functools import partial
from oslo_log import log as logging
from neutron_lib import exceptions as n_exceptions

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
get_network_client = partial(_get_client, cls=NetworkManagementClient)


def _perform_and_wait(operation, args=(), kwargs={}, timeout=300):
    operation(*args, **kwargs).wait(timeout=timeout)


def create_network(network, resource_group, name, info):
    _perform_and_wait(network.virtual_networks.create_or_update,
                      (resource_group, name, info))


def delete_network(network, resource_group, name):
    _perform_and_wait(network.virtual_networks.delete, (resource_group, name))


def get_network(network, resource_group, name):
    try:
        return network.virtual_networks.get(resource_group, name)
    except CloudError:
        raise n_exceptions.NetworkNotFound(net_id=name)


def create_subnet(network, resource_group, network_name, name, info):
    _perform_and_wait(network.subnets.create_or_update,
                      (resource_group, network_name, name, info))


def delete_subnet(network, resource_group, network_name, name):
    _perform_and_wait(network.subnets.delete, (resource_group, network_name,
                                               name))


def get_subnet(network, resource_group, network_name, name):
    try:
        return network.subnets.get(resource_group, network_name, name)
    except CloudError:
        raise n_exceptions.SubnetNotFound(subnet_id=name)
