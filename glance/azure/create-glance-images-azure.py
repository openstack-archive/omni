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
import hashlib
import os
import sys
import uuid

import azureutils
import keystoneauth1
import requests

from keystoneauth1 import loading
from keystoneauth1 import session
from keystoneclient import client


def get_env_param(env_name):
    if env_name in os.environ:
        return os.environ[env_name]
    raise Exception("%s environment variable not set." % env_name)


def get_keystone_session(
        auth_url=get_env_param('OS_AUTH_URL'),
        project_name=os.environ.get('OS_PROJECT_NAME'),
        tenant_name=os.environ.get('OS_TENANT_NAME'),
        project_domain_name=os.environ.get('OS_PROJECT_DOMAIN_NAME',
                                           'default'),
        user_domain_name=os.environ.get('OS_USER_DOMAIN_NAME', 'default'),
        username=get_env_param('OS_USERNAME'),
        password=get_env_param('OS_PASSWORD')):

    if not project_name:
        if not tenant_name:
            raise Exception("Either OS_PROJECT_NAME or OS_TENANT_NAME is "
                            "required.")
        project_name = tenant_name

    loader = loading.get_plugin_loader('password')
    auth = loader.load_from_options(
        auth_url=auth_url, project_name=project_name,
        project_domain_name=project_domain_name, username=username,
        user_domain_name=user_domain_name, password=password)
    sess = session.Session(auth=auth)
    return sess


class AzureImages(object):

    def __init__(self, tenant_id, client_id, client_secret, subscription_id,
                 region):
        self.compute = azureutils.get_azure_client(
            tenant_id, client_id, client_secret, subscription_id)
        self.region = region
        self.image_kind = {'RAW': 'raw'}
        self.glance_client = RestClient()

    def register_azure_images(self):
        for image in azureutils.get_vm_images(self.compute, self.region):
            image_data = self._azure_to_openstack_formatter(image)
            self.create_image(image_data)

    def _azure_to_openstack_formatter(self, azure_image_data):
        """Converts Azure image data to Openstack image data format.
        :param img(dict): gce img data
        :return(dict): ostack img data
        """
        name = azure_image_data['id'].split('Skus')[1].split("/")[1]
        return {'id': self._get_image_uuid(azure_image_data['id']),
                'name': name,
                'container_format': 'bare',
                'disk_format': self.image_kind[azure_image_data['sourceType']],
                'visibility': 'public',
                'azure_link': azure_image_data['id']}

    def _get_image_uuid(self, azure_id):
        md = hashlib.md5()
        md.update(azure_id)
        return str(uuid.UUID(bytes=md.digest()))

    def create_image(self, image_data):
        """Create an OpenStack image.
        :param image_data: dict -- Describes Azure Image
        :returns: dict -- Response from REST call
        :raises: requests.HTTPError
        """
        glance_id = image_data['id']
        azure_id = image_data['name']
        print "Creating image: {0}".format(azure_id)
        azure_link = image_data['azure_link']
        subscription_id = self._get_subscription_id(azure_link)
        image_properties = {
            'locations': [{
                'url': 'azure://%s/%s/%s' % (subscription_id, azure_id,
                                             glance_id),
                'metadata': {'azure_link': azure_link}}]
        }
        try:
            resp = self.glance_client.request('POST', '/v2/images',
                                              json=image_data)
            resp.raise_for_status()
            # Need to update the image in the registry
            # with location information so
            # the status changes from 'queued' to 'active'
            self.update_properties(glance_id, image_properties)
            print "Created image: {0}".format(azure_id)
        except keystoneauth1.exceptions.http.Conflict:
            # ignore error if image already exists
            pass
        except requests.HTTPError as e:
            raise e

    def _get_subscription_id(self, azure_link):
        return azure_link.split('Subscriptions')[1].split("/")[1]

    def update_properties(self, image_id, properties):
        """Add or update a set of image properties on an image.
        :param image_id: int -- The Openstack image UUID
        :param properties: dict -- Image properties to update
        """
        if not properties:
            return
        patch_body = []
        for name, value in properties.iteritems():
            patch_body.append({'op': 'replace',
                               'path': '/%s' % name,
                               'value': value})
        resp = self.glance_client.request('PATCH', '/v2/images/%s' % image_id,
                                          json=patch_body)
        resp.raise_for_status()


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
        """Make a requests request with retry/relogin on auth failure."""
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
    if len(sys.argv) != 6:
        msg = 'Usage: {0} <tenant_id> <client_id> <client_secret> '
        msg += '<subscription_id> <region>'
        print msg.format(sys.argv[0])
        sys.exit(1)

    azure_images = AzureImages(sys.argv[1], sys.argv[2], sys.argv[3],
                               sys.argv[4], sys.argv[5])
    azure_images.register_azure_images()
