# Copyright (c) 2016 Platform9 Systems Inc. (http://www.platform9.com)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
'''
1. Source openstack RC file
2. python create-nova-flavors-gce.py <service_key_path> <project> <zone>
'''

import os
import sys
import gceutils

from novaclient import client as nova_client
from keystoneauth1 import loading, session


def get_keystone_session(
        auth_url=os.environ['OS_AUTH_URL'],
        project_name=os.environ.get('OS_PROJECT_NAME', ''),
        tenant_name=os.environ.get('OS_TENANT_NAME', ''),
        project_domain_name=os.environ.get('OS_PROJECT_DOMAIN_NAME',
                                           'default'),  # noqa
        username=os.environ['OS_USERNAME'],
        user_domain_name=os.environ.get('OS_USER_DOMAIN_NAME', 'default'),
        password=os.environ['OS_PASSWORD']):

    if not project_name:
        if not tenant_name:
            raise Exception("OS_PROJECT_NAME or OS_TENANT_NAME not set.")
        project_name = tenant_name

    loader = loading.get_plugin_loader('password')
    auth = loader.load_from_options(
        auth_url=auth_url, project_name=project_name,
        project_domain_name=project_domain_name, username=username,
        user_domain_name=user_domain_name, password=password)
    sess = session.Session(auth=auth)
    return sess


class GceFlavors(object):
    def __init__(self, service_key_path, project, zone):
        self.gce_svc = gceutils.get_gce_service(service_key_path)
        self.project = project
        self.zone = zone

        auth_url = os.environ['OS_AUTH_URL']
        if auth_url.find('v2.0') > 0:
            auth_url = auth_url.replace('v2.0', 'v3')
        self.auth_url = auth_url
        self.sess = get_keystone_session(auth_url=self.auth_url)
        self.nova_client = nova_client.Client('2', session=self.sess)

    def register_gce_flavors(self):
        flavors = gceutils.get_machines_info(self.gce_svc, self.project,
                                             self.zone)
        for flavor_name, flavor_info in flavors.iteritems():
            self.nova_client.flavors.create(
                flavor_name, flavor_info['memory_mb'], flavor_info['vcpus'], 0)
            print("Registered flavor %s" % flavor_name)


if __name__ == '__main__':
    if len(sys.argv) != 4:
        sys.stderr.write(
            'Incorrect usage: this script takes exactly 4 arguments.\n')
        sys.exit(1)
    gce_flavors = GceFlavors(sys.argv[1], sys.argv[2], sys.argv[3])
    gce_flavors.register_gce_flavors()
