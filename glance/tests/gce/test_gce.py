# Copyright (c) 2017 Platform9 Systems Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import os
import mock

from glance_store import exceptions
from glance_store import location
from glance_store.location import Location
from glance_store._drivers.gce import Store
from glance_store._drivers.gce import StoreLocation
from glance.tests.unit.gce import gce_mock
from glance.tests import utils
from oslo_config import cfg
from oslo_utils import units

DATA_DIR = os.path.dirname(os.path.abspath(__file__)) + '/data'


class GCEGlanceTestCase(utils.BaseTestCase):
    @mock.patch('glance_store._drivers.gceutils.get_gce_service')
    def setUp(self, mock_service):
        mock_service.side_effect = gce_mock.get_gce_service
        super(GCEGlanceTestCase, self).setUp()
        self.store = Store(cfg.CONF)
        self.store.gce_zone = 'us-central1-c'
        self.store.gce_project = 'omni-163105'
        self.store.gce_svc_key = "{0}/omni.json".format(DATA_DIR)

    @mock.patch('glance_store._drivers.gceutils.get_image')
    def test_get_size(self, mock_get):
        mock_get.side_effect = gce_mock.get_image
        store_specs = {
            'gce_project': 'omni-163105',
            'gce_id': 'fake_gce_id',
            'glance_id': 'fake_glance_id'
        }
        location = Location("gce", StoreLocation, cfg.CONF,
                            store_specs=store_specs)
        size = self.store.get_size(location)
        self.assertTrue(isinstance(size, int))
        self.assertEqual(size, 10 * units.Gi)

    def test_store_location_initialization(self):
        location.SCHEME_TO_CLS_MAP["gce"] = {}
        location.SCHEME_TO_CLS_MAP['gce']['location_class'] = StoreLocation
        uri = "gce://%s/fake_gce_id/fake_glance_id" % (self.store.gce_project)
        self.assertTrue(
            isinstance(location.get_location_from_uri(uri), Location))

    def test_store_location_initialization_with_invalid_url(self):
        location.SCHEME_TO_CLS_MAP["scheme"] = {}
        location.SCHEME_TO_CLS_MAP['scheme']['location_class'] = StoreLocation
        uri = "scheme://%s/fake_gce_id/fake_glance_id" % (
            self.store.gce_project)
        self.assertRaises(exceptions.BadStoreUri,
                          location.get_location_from_uri, uri)
