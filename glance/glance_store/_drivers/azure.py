"""
Copyright (c) 2017 Platform9 Systems Inc. (http://www.platform9.com)
Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""
import logging
import os

from googleapiclient.errors import HttpError
from oslo_config import cfg
from oslo_utils import units

import azureutils
from glance_store import capabilities
import glance_store.driver
from glance_store import exceptions
from glance_store.i18n import _
import glance_store.location
from six.moves import urllib

LOG = logging.getLogger(__name__)

MAX_REDIRECTS = 5
STORE_SCHEME = 'azure'

azure_group = cfg.OptGroup(name='azure',
                           title='Options to connect to Azure cloud')

azure_opts = [cfg.StrOpt('tenant_id', help='Tenant ID of Azure account'),
              cfg.StrOpt('client_id', help='Client ID/Application ID'),
              cfg.StrOpt('client_secret', help='Client Secret'),
              cfg.StrOpt('subscription_id', help='Subscription ID of Azure'),
              cfg.StrOpt('region', help='Azure region')]


class StoreLocation(glance_store.location.StoreLocation):
    """Class describing Azure URI."""

    def __init__(self, store_specs, conf):
        super(StoreLocation, self).__init__(store_specs, conf)

    def process_specs(self):
        self.scheme = self.specs.get('scheme', STORE_SCHEME)
        self.subscription_id = self.specs.get('subscription_id')
        self.azure_id = self.specs.get('azure_id')
        self.glance_id = self.specs.get('glance_id')

    def get_uri(self):
        return "{0}://{1}/{2}/{3}".format(self.scheme, self.subscription_id,
                                          self.azure_id, self.glance_id)

    def parse_uri(self, uri):
        """Parse URLs based on Azure scheme """
        LOG.debug('Parse uri %s' % (uri, ))
        if not uri.startswith('%s://' % STORE_SCHEME):
            reason = (_("URI %(uri)s must start with %(scheme)s://") % {
                'uri': uri, 'scheme': STORE_SCHEME})
            LOG.error(reason)
            raise exceptions.BadStoreUri(message=reason)
        pieces = urllib.parse.urlparse(uri)
        self.scheme = pieces.scheme
        subscription_id = pieces.netloc
        azure_id, glance_id = pieces.path.strip('/').split('/')
        parse_params = (subscription_id, azure_id, glance_id)
        if not all([parse_params]):
            raise exceptions.BadStoreUri(uri=uri)
        self.subscription_id, self.azure_id, self.glance_id = parse_params


class Store(glance_store.driver.Store):
    """An implementation of the HTTP(S) Backend Adapter"""

    _CAPABILITIES = (capabilities.BitMasks.RW_ACCESS |
                     capabilities.BitMasks.DRIVER_REUSABLE)

    def __init__(self, conf):
        super(Store, self).__init__(conf)
        conf.register_group(azure_group)
        conf.register_opts(azure_opts, group=azure_group)
        self.tenant_id = conf.azure.tenant_id
        self.client_id = conf.azure.client_id
        self.client_secret = conf.azure.client_secret
        self.subscription_id = conf.azure.subscription_id
        self.region = conf.azure.region
        self._azure_client = None
        LOG.info('Initialized Azure Glance Store driver')

    def get_schemes(self):
        return ('azure', )

    @property
    def azure_client(self):
        if self._azure_client is None:
            self._azure_client = azureutils.get_azure_client(
                self.tenant_id, self.client_id, self.client_secret,
                self.subscription_id)
        return self._azure_client

    @capabilities.check
    def get(self, location, offset=0, chunk_size=None, context=None):
        """Takes a `glance_store.location.Location` object that indicates
        where to find the image file, and returns a tuple of generator
        (for reading the image file) and image_size

        :param location `glance_store.location.Location` object, supplied
                        from glance_store.location.get_location_from_uri()
        """
        raise NotImplementedError("Azure does not support this operation")

    @capabilities.check
    def add(self, image_id, image_file, image_size, context=None,
            verifier=None):
        """Stores an image file with supplied identifier to the backend
        storage system and returns a tuple containing information
        about the stored image.

        :param image_id: The opaque image identifier
        :param image_file: The image data to write, as a file-like object
        :param image_size: The size of the image data to write, in bytes

        :retval: tuple of URL in backing store, bytes written, checksum
               and a dictionary with storage system specific information
        :raises: `glance_store.exceptions.Duplicate` if the image already
                existed
        """
        # Adding images is not suppported yet
        raise NotImplementedError("This operation is not supported in Azure")

    @capabilities.check
    def delete(self, location, context=None):
        """Takes a `glance_store.location.Location` object that indicates
        where to find the image file to delete

        :param location: `glance_store.location.Location` object, supplied
                  from glance_store.location.get_location_from_uri()
        :raises NotFound if image does not exist
        """
        # This method works for GCE public images as we just need to delete
        # entry from glance catalog.
        # For Private images we will need extra handling here.
        LOG.info("Delete image %s" % location.get_store_uri())
