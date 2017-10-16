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

from azure.mgmt.network import models as network_models
from azure.mgmt.resource.resources import models as resource_models
from devtools_testutils.mgmt_testcase import fake_settings


class Response(object):
    def __init__(self):
        self.status_code = 400


class FakeNeutronManager(object):
    def get_security_group_rule(self, context, rule_id):
        data = {'id': 'fake_rule_id',
                'security_group_id': '4cd70774-cc67-4a87-9b39-7d1db38eb087',
                'direction': 'ingress',
                'protocol': 'tcp',
                'ethertype': 'IPv4',
                'tenant_id': 'fake_tenant_id',
                'port_range_min': '22',
                'port_range_max': '22',
                'remote_ip_prefix': None,
                'remote_group_id': None}
        return data


def get_fake_credentials(tenant_id, client_id, client_secret):
    return fake_settings.get_credentials()


def get_fake_resource_group(client, resource_group):
    resource_group = resource_models.Resource(location='eastus')
    return resource_group


def get_fake_network(client, resource_group, network_name):
    network = network_models.VirtualNetwork()
    network.name = network_name
    address_space = network_models.AddressSpace(address_prefixes=[])
    network.address_space = address_space
    return network


def get_fake_subnet(client, resource_group, network_name, subnet_name):
    subnet = network_models.Subnet()
    subnet.name = subnet_name
    subnet.id = "fake_subnet_id"
    return subnet


def get_fake_sg(client, resource_group, sg_name):
    sg = network_models.SecurityGroupNetworkInterface()
    sg.id = 'fake_sg_id'
    sg.security_rules = []
    return sg


def get_fake_nic(client, resource_group, nic_name):
    nic = network_models.NetworkInterface()
    ip_configurations = network_models.IPConfiguration()
    ip_configurations.name = "fake_ip_configuration_name"
    nic.ip_configurations = [ip_configurations]
    return nic


def get_fake_public_ip(client, resource_group, region):
    public_ip = network_models.PublicIPAddress()
    public_ip.ip_address = "192.168.1.5"
    public_ip.name = "fake_public_ip"
    return public_ip


def create_anything(*args, **kwargs):
    return None


def delete_anything(*args, **kwargs):
    return None
