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

import mock

from azure.mgmt.compute import models as compute_models
from azure.mgmt.resource.resources import models as resource_models
from devtools_testutils.mgmt_testcase import fake_settings
from glance_store._drivers.azure.store import Store
from glance_store._drivers.azure.store import StoreLocation
from glance_store import exceptions
from glance_store import location
from glance_store.location import Location
from glance_store.tests import base
from oslo_config import cfg

RESOURCE_GROUP = 'omni_test_group'
CLIENT_SECRET = 'fake_key'


def get_fake_resource_group(client, resource_group):
    resource_group = resource_models.Resource(location='eastus')
    return resource_group


def fake_get_credentials(tenant_id, client_id, client_secret):
    return fake_settings.get_credentials()


def fake_get_image(compute, resource_group, name):
    storage_profile = compute_models.ImageStorageProfile(
        compute_models.ImageOSDisk('Linux', 'Generalized'))
    _image = compute_models.Image(location='eastus')
    _image.storage_profile = storage_profile
    return _image


class AzureGlanceTestCase(base.StoreBaseTest):
    @mock.patch(
        "cinder.volume.drivers.azure.azureutils.check_resource_existence")
    def setUp(self, mock_check):
        super(AzureGlanceTestCase, self).setUp()
        mock_check.side_effect = get_fake_resource_group
        self.creds_patcher = mock.patch(
            'glance_store._drivers.azure.utils.get_credentials').start()
        mock_creds = self.creds_patcher.start()
        mock_creds.side_effect = fake_get_credentials
        self.addCleanup(self.creds_patcher.stop)
        self.store = Store(cfg.CONF)
        self.store.tenant_id = fake_settings.TENANT_ID
        self.store.subscription_id = fake_settings.SUBSCRIPTION_ID
        self.store.client_id = fake_settings.CLIENT_OID
        self.store.client_secret = CLIENT_SECRET
        self.store.resource_group = RESOURCE_GROUP
        self.scheme = "azure"

    @mock.patch('glance_store._drivers.azure.utils.get_image')
    def test_get_size(self, mock_get):
        mock_get.side_effect = fake_get_image
        store_specs = {}
        attrs_values = [
            self.store.subscription_id, 'Microsoft.Compute',
            self.store.resource_group, 'myImage'
        ]
        for attr, value in zip(StoreLocation.uri_attrs, attrs_values):
            store_specs[attr] = value
        location = Location("azure", StoreLocation, cfg.CONF,
                            store_specs=store_specs)
        self.assertEqual(location.store_location.images, "myImage")
        size = self.store.get_size(location)
        self.assertIsInstance(size, int)
        self.assertEqual(1, size)

    def test_store_location_initialization(self):
        location.SCHEME_TO_CLS_MAP['azure'] = {}
        location.SCHEME_TO_CLS_MAP['azure']['location_class'] = StoreLocation
        _uri_path = []
        attrs_values = [
            self.store.subscription_id, 'Microsoft.Compute',
            self.store.resource_group, 'myImage'
        ]
        for attr, value in zip(StoreLocation.uri_attrs, attrs_values):
            _uri_path.extend([attr, value])
        uri = "{0}://{1}/{2}".format(self.scheme, "/".join(_uri_path),
                                     "fake_glance_id")
        self.assertIsInstance(location.get_location_from_uri(uri), Location)

    def test_store_location_initialization_with_invalid_url(self):
        location.SCHEME_TO_CLS_MAP["scheme"] = {}
        location.SCHEME_TO_CLS_MAP['scheme']['location_class'] = StoreLocation
        uri = "scheme:///fake_image_id"
        self.assertRaises(exceptions.BadStoreUri,
                          location.get_location_from_uri, uri)
