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

import os

from apiclient.http import HttpMock
from googleapiclient.discovery import build

DATA_DIR = os.path.dirname(os.path.abspath(__file__)) + '/data'


def fake_operation():
    return {'name': 'fake_operation'}


def get_gce_service(service_key):
    http = HttpMock(DATA_DIR + '/service/service_data.json', {'status': '200'})
    service = build('compute', 'v1', http=http, developerKey=service_key)
    return service


def get_network(compute, project, name):
    http = HttpMock(DATA_DIR + '/network/get_network.json', {'status': '200'})
    request = compute.networks().get(project=project, network=name)
    response = request.execute(http=http)
    return response


def get_firewall_rule(compute, project, name):
    http = HttpMock(DATA_DIR + '/network/get_firewall.json', {'status': '200'})
    request = compute.firewalls().get(project=project, firewall=name)
    response = request.execute(http=http)
    return response


def create_anything(*args, **kwargs):
    return fake_operation()


def wait_for_operation(*args, **kwargs):
    pass


def delete_anything(*args, **kwargs):
    return fake_operation()


def return_nothing(*args, **kwargs):
    pass


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
