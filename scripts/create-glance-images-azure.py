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
from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.compute import ComputeManagementClient
from functools import partial
from glanceclient import Client
from keystoneauth1 import loading
from keystoneauth1 import session

import hashlib
import os
import sys
import uuid


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
    auth = loader.load_from_options(
        auth_url=auth_url, project_name=project_name,
        username=username, password=password)
    sess = session.Session(auth=auth)
    return sess


def get_glance_client(vendor_data):
    GLANCE_VERSION = '2'
    glance_client = Client(GLANCE_VERSION,
                           session=get_keystone_session(vendor_data))
    return glance_client


class GlanceOperator(object):
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
        self.vendor_data = {'username': username,
                            'password': password,
                            'auth_url': auth_url,
                            'tenant_name': project_name}
        self.glance_client = get_glance_client(self.vendor_data)

    def register_image(self, image):
        locations = image.pop('locations')
        response = self.glance_client.images.create(**image)
        glance_id = response['id']
        for location in locations:
            self.glance_client.images.add_location(glance_id, location['url'],
                                                   location['metadata'])
        print("Registered image %s" % image['name'])


class ImageProvider(object):
    def __init__(self):
        self.glance_operator = GlanceOperator()

    def get_public_images(self):
        raise NotImplementedError()

    def register_images(self):
        for image_info in self.get_public_images():
            self.glance_operator.register_image(image_info)


class AzureImages(ImageProvider):
    def __init__(self):
        super(AzureImages, self).__init__()
        tenant_id = get_env_param('AZURE_TENANT_ID')
        client_id = get_env_param('AZURE_CLIENT_ID')
        client_secret = get_env_param('AZURE_CLIENT_SECRET')
        subscription_id = get_env_param('AZURE_SUBSCRIPTION_ID')
        self.region = get_env_param('AZURE_REGION')
        self.resource_group = get_env_param('AZURE_RESOURCE_GROUP')
        self.compute_client = get_compute_client(
            tenant_id, client_id, client_secret, subscription_id)

    def _azure_to_openstack_formatter(self, image_info):
        """Converts Azure image data to Openstack image data format."""
        image_uuid = self._get_image_uuid(image_info.id)
        location_info = [
            {
                'url': 'azure://{0}/{1}'.format(image_info.id.strip('/'),
                                                image_uuid),
                'metadata': {'azure_link': image_info.id}
            },
        ]
        return {'id': image_uuid,
                'name': image_info.name,
                'container_format': 'bare',
                'disk_format': 'raw',
                'visibility': 'public',
                'azure_link': image_info.id,
                'locations': location_info}

    def _get_image_uuid(self, azure_id):
        md = hashlib.md5()
        md.update(azure_id)
        return str(uuid.UUID(bytes=md.digest()))

    def get_public_images(self):
        images = self.compute_client.images
        response = images.list_by_resource_group(self.resource_group)
        for result in response.advance_page():
            image_response = images.get(self.resource_group, result.name)
            yield self._azure_to_openstack_formatter(image_response)


if __name__ == '__main__':
    az_images = AzureImages()
    az_images.register_images()
