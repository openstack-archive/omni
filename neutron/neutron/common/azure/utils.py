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
import uuid

from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from msrestazure.azure_exceptions import CloudError
from oslo_log import log as logging

from neutron.extensions import securitygroup as sg
from neutron_lib import exceptions as n_exceptions

LOG = logging.getLogger(__name__)


class FloatingIPNotFound(n_exceptions.NotFound):
    message = "Floating IP %(ip)s could not be found."


def azure_handle_exception(fn):
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            LOG.exception("Exception occurred in Azure operation: %s" %
                          (e.message))

    return wrapper


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


@azure_handle_exception
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


@azure_handle_exception
def delete_subnet(network, resource_group, network_name, name):
    _perform_and_wait(network.subnets.delete, (resource_group, network_name,
                                               name))


def get_subnet(network, resource_group, network_name, name):
    try:
        return network.subnets.get(resource_group, network_name, name)
    except CloudError:
        raise n_exceptions.SubnetNotFound(subnet_id=name)


def get_nic(network, resource_group, name):
    try:
        return network.network_interfaces.get(resource_group, name)
    except CloudError:
        raise n_exceptions.PortNotFound(port_id=name)


def create_nic(network, resource_group, name, body):
    _perform_and_wait(network.network_interfaces.create_or_update,
                      (resource_group, name, body))


@azure_handle_exception
def delete_nic(network, resource_group, name):
    _perform_and_wait(network.network_interfaces.delete, (resource_group,
                                                          name))


def get_sg(network, resource_group, name):
    return network.network_security_groups.get(resource_group, name)


def create_sg(network, resource_group, name, body):
    _perform_and_wait(network.network_security_groups.create_or_update,
                      (resource_group, name, body))


@azure_handle_exception
def delete_sg(network, resource_group, name):
    _perform_and_wait(network.network_security_groups.delete, (resource_group,
                                                               name))


def get_sg_rule(network, resource_group, sg_name, name):
    return network.network_security_rules.get(resource_group, sg_name, name)


def create_sg_rule(network, resource_group, sg_name, name, body):
    _perform_and_wait(network.security_rules.create_or_update,
                      (resource_group, sg_name, name, body))


@azure_handle_exception
def delete_sg_rule(network, resource_group, sg_name, name):
    _perform_and_wait(network.security_rules.delete, (resource_group, sg_name,
                                                      name))


# Maintaining different calls for update to simplify mocking
update_network = create_network
update_nic = create_nic
update_sg = create_sg
update_sg_rule = create_sg_rule


def convert_sg_rule(openstack_rule, priority=None):
    directions = {'ingress': 'Inbound', 'egress': 'Outbound'}
    protocols = {'tcp': 'Tcp', 'udp': 'Udp'}

    # Asterix '*' is used to match all possible values.
    # E.g. In case of source_port_range it will allow all ports.
    # The default security group is allow all traffic, based on
    # user inputs we refine it further.
    sg_rule = {
        'source_port_range': '*',
        'destination_port_range': '*',
        'source_address_prefix': '*',
        'destination_address_prefix': '*',
        'access': 'Allow',
        'priority': priority
    }
    sg_rule['direction'] = directions[openstack_rule['direction']]

    if openstack_rule['ethertype'] != 'IPv4':
        raise sg.SecurityGroupRuleInvalidEtherType(
            ethertype=openstack_rule['ethertype'], values=('IPv4', ))

    protocol = openstack_rule['protocol']
    if protocol is None:
        sg_rule['protocol'] = '*'
    if protocol and protocol in protocols:
        sg_rule['protocol'] = protocols[protocol]
    else:
        raise sg.SecurityGroupRuleInvalidProtocol(
            protocol=protocol, values=protocols.keys())

    port_range_min = openstack_rule['port_range_min']
    port_range_max = openstack_rule['port_range_max']
    if port_range_min and port_range_min == port_range_max:
        sg_rule['destination_port_range'] = str(port_range_min)
    elif port_range_min and port_range_max:
        sg_rule['destination_port_range'] = "%s-%s" % (port_range_min,
                                                       port_range_max)

    if openstack_rule['remote_ip_prefix']:
        # TODO(ssudake21): Allow support for tags in source_address_prefix
        sg_rule['source_address_prefix'] = openstack_rule['remote_ip_prefix']

    return sg_rule


def allocate_floatingip(network, resource_group, region):
    name = 'eip-' + str(uuid.uuid4())
    data = {
        'location': region,
        'public_ip_allocation_method': 'Static',
        'public_ip_address_version': 'IPv4',
        'idle_timeout_in_minutes': 4
    }
    response = network.public_ip_addresses.create_or_update(
        resource_group, name, data)
    return response.result()


def get_floatingip(network, resource_group, ip):
    for public_ip in network.public_ip_addresses.list(resource_group):
        if public_ip.ip_address == ip:
            return public_ip
    raise FloatingIPNotFound(ip=ip)


@azure_handle_exception
def delete_floatingip(network, resource_group, public_ip_name):
    _perform_and_wait(network.public_ip_addresses.delete, (resource_group,
                                                           public_ip_name))
