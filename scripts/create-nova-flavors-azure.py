"""
Copyright (c) 2017 Platform9 Systems Inc. (http://www.platform9.com)
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import os
import sys
import utils as azure_utils

from keystoneauth1 import loading
from keystoneauth1 import session
from novaclient import client as nova_client


def abort(message):
    sys.exit(message)


def get_env_param(env_name):
    if env_name in os.environ:
        return os.environ[env_name]
    abort("%s environment variable not set." % env_name)


def get_keystone_session(vendor_data):
    username = vendor_data['username']
    password = vendor_data['password']
    project_name = vendor_data['tenant_name']
    auth_url = vendor_data['auth_url']

    loader = loading.get_plugin_loader('password')
    auth = loader.load_from_options(auth_url=auth_url,
                                    project_name=project_name,
                                    username=username, password=password)
    sess = session.Session(auth=auth)
    return sess


def get_nova_client(vendor_data):
    NOVA_VERSION = '2'
    client = nova_client.Client(NOVA_VERSION,
                                session=get_keystone_session(vendor_data))
    return client


class NovaOperator(object):
    def __init__(self):
        auth_url = get_env_param('OS_AUTH_URL')
        project_name = os.environ.get('OS_PROJECT_NAME')
        tenant_name = os.environ.get('OS_TENANT_NAME')
        username = get_env_param('OS_USERNAME')
        password = get_env_param('OS_PASSWORD')
        if not project_name:
            if not tenant_name:
                raise Exception("Either OS_PROJECT_NAME or OS_TENANT_NAME is "
                                "required.")
            project_name = tenant_name
        self.vendor_data = {
            'username': username,
            'password': password,
            'auth_url': auth_url,
            'tenant_name': project_name
        }
        self.nova_client = get_nova_client(self.vendor_data)

    def register_flavor(self, name, memory_mb=0, vcpus=0):
        self.nova_client.flavors.create(name, memory_mb, vcpus, 0)
        print("Registered flavor %s" % name)


class FlavorProvider(object):
    def __init__(self):
        self.nova_operator = NovaOperator()

    def get_flavor_objs(self):
        raise NotImplementedError()

    def register_flavors(self):
        for flavor_info in self.get_flavor_objs():
            self.nova_operator.register_flavor(flavor_info.name,
                                               flavor_info.memory_in_mb,
                                               flavor_info.number_of_cores)


class AzureFlavors(FlavorProvider):
    def __init__(self):
        super(AzureFlavors, self).__init__()
        tenant_id = get_env_param('AZURE_TENANT_ID')
        client_id = get_env_param('AZURE_CLIENT_ID')
        client_secret = get_env_param('AZURE_CLIENT_SECRET')
        subscription_id = get_env_param('AZURE_SUBSCRIPTION_ID')
        self.region = get_env_param('AZURE_REGION')
        self.compute_client = azure_utils.get_compute_client(
            tenant_id, client_id, client_secret, subscription_id)

    def get_flavor_objs(self):
        vm_sizes = self.compute_client.virtual_machine_sizes
        for i in vm_sizes.list(location=self.region):
            yield i


if __name__ == '__main__':
    az_flavors = AzureFlavors()
    az_flavors.register_flavors()
