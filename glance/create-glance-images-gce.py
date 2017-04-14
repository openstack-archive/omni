# Copyright (c) 2017 Platform9 Systems Inc. (http://www.platform9.com)
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
1. Export Openstack RC file
2. Run this script as: python create-glance-credentials.py <service-key-path>
'''

import hashlib
import os
import requests
import sys
import uuid
import keystoneauth1
import gceutils

from keystoneauth1 import loading, session
from keystoneclient import client
from six.moves import urllib


def get_env_param(env_name):
    if env_name in os.environ:
        return os.environ[env_name]
    raise Exception("%s environment variable not set." % env_name)


def get_keystone_session(
        auth_url=get_env_param('OS_AUTH_URL'),
        project_name=os.environ.get('OS_PROJECT_NAME', ''),
        tenant_name=os.environ.get('OS_TENANT_NAME', ''),
        project_domain_name=os.environ.get('OS_PROJECT_DOMAIN_NAME',
                                           'default'),  # noqa
        username=get_env_param('OS_USERNAME'),
        user_domain_name=os.environ.get('OS_USER_DOMAIN_NAME', 'default'),
        password=get_env_param('OS_PASSWORD')):

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


class GceImages(object):
    GC_PUBLIC_PROJECTS = [
        'cos-cloud', 'centos-cloud', 'debian-cloud', 'rhel-cloud',
        'suse-cloud', 'ubuntu-os-cloud', 'windows-cloud'
    ]

    def __init__(self, service_key_path):
        self.gce_svc = gceutils.get_gce_service(service_key_path)
        self.img_kind = {
            'RAW': 'raw',
        }
        self.glance_client = RestClient()

    def get_all_public_images(self):
        images = []
        for project in self.GC_PUBLIC_PROJECTS:
            images.extend(gceutils.get_images(self.gce_svc, project))
        return images

    def register_gce_images(self):
        for image in self.get_all_public_images():
            self.create_image(self._gce_to_ostack_formatter(image))

    def _get_project(self, gce_link):
        parsed_link = urllib.parse.urlparse(gce_link)
        project = parsed_link.path.strip('/').split('/')[3]
        return project

    def create_image(self, img_data):
        """
        Create an OpenStack image.
        :param img_data: dict -- Describes GCE Image
        :returns: dict -- Response from REST call
        :raises: requests.HTTPError
        """
        glance_id = img_data['id']
        gce_id = img_data['name']
        print("Creating image: {0}".format(gce_id))
        gce_link = img_data['gce_link']
        gce_project = self._get_project(gce_link)
        img_props = {
            'locations': [{
                'url':
                'gce://%s/%s/%s' % (gce_project, gce_id, glance_id),
                'metadata': {
                    'gce_link': gce_link
                }
            }]
        }
        try:
            resp = self.glance_client.request('POST', '/v2/images',
                                              json=img_data)
            resp.raise_for_status()
            # Need to update the image in the registry
            # with location information so
            # the status changes from 'queued' to 'active'
            self.update_properties(glance_id, img_props)
        except keystoneauth1.exceptions.http.Conflict:
            # ignore error if image already exists
            pass
        except requests.HTTPError as e:
            raise e
        print("Created image: {0}".format(gce_id))

    def update_properties(self, imageid, props):
        """
        Add or update a set of image properties on an image.
        :param imageid: int -- The Ostack image UUID
        :param props: dict -- Image properties to update
        """
        if not props:
            return
        patch_body = []
        for name, value in props.iteritems():
            patch_body.append({
                'op': 'replace',
                'path': '/%s' % name,
                'value': value
            })
        resp = self.glance_client.request('PATCH', '/v2/images/%s' % imageid,
                                          json=patch_body)
        resp.raise_for_status()

    def _get_image_uuid(self, gce_id):
        md = hashlib.md5()
        md.update(gce_id)
        return str(uuid.UUID(bytes=md.digest()))

    def _gce_to_ostack_formatter(self, gce_img_data):
        """
        Converts GCE img data to Openstack img data format.
        :param img(dict): gce img data
        :return(dict): ostack img data
        """
        return {
            'id': self._get_image_uuid(gce_img_data['id']),
            'name': gce_img_data['name'],
            'container_format': 'bare',
            'disk_format': self.img_kind[gce_img_data['sourceType']],
            'visibility': 'public',
            'gce_image_id': gce_img_data['id'],
            'gce_size': gce_img_data['diskSizeGb'],
            'gce_link': gce_img_data['selfLink']
        }


class RestClient(object):
    def __init__(self):
        auth_url = get_env_param('OS_AUTH_URL')
        if auth_url.find('v2.0') > 0:
            auth_url = auth_url.replace('v2.0', 'v3')
        self.auth_url = auth_url
        self.region_name = get_env_param('OS_REGION_NAME')
        self.sess = get_keystone_session(auth_url=self.auth_url)
        self.glance_endpoint = self.get_glance_endpoint()

    def get_glance_endpoint(self):
        self.ksclient = client.Client(auth_url=self.auth_url,
                                      session=self.sess)
        glance_service_id = self.ksclient.services.list(name='glance')[0].id
        glance_url = self.ksclient.endpoints.list(
            service=glance_service_id, interface='public', enabled=True,
            region=self.region_name)[0].url
        return glance_url

    def request(self, method, path, **kwargs):
        """
        Make a requests request with retry/relogin on auth failure.
        """
        url = self.glance_endpoint + path
        headers = self.sess.get_auth_headers()
        if method == 'PUT' or method == 'PATCH':
            headers['Content-Type'] = '/'.join(
                ['application', 'openstack-images-v2.1-json-patch'])
            resp = requests.request(method, url, headers=headers, **kwargs)
        else:
            resp = self.sess.request(url, method, headers=headers, **kwargs)
        resp.raise_for_status()
        return resp


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.stderr.write(
            'Incorrect usage: this script takes exactly 2 arguments.\n')
        sys.exit(1)

    gce_images = GceImages(sys.argv[1])
    gce_images.register_gce_images()
