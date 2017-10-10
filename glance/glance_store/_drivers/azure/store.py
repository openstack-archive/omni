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

from oslo_utils import units

from glance_store._drivers.azure import config
from glance_store._drivers.azure import utils
from glance_store import capabilities
from glance_store import driver
from glance_store import exceptions
from glance_store.i18n import _
from glance_store import location
from six.moves import urllib

LOG = logging.getLogger(__name__)

MAX_REDIRECTS = 5
STORE_SCHEME = 'azure'


class StoreLocation(location.StoreLocation):
    """Class describing Azure URI."""
    uri_attrs = ['subscriptions', 'providers', 'resourcegroups', 'images']

    def __init__(self, store_specs, conf):
        super(StoreLocation, self).__init__(store_specs, conf)
        self._sorted_uri_attrs = sorted(self.uri_attrs)

    def process_specs(self):
        self.scheme = self.specs.get('scheme', STORE_SCHEME)
        for attr in self.uri_attrs:
            setattr(self, attr, self.specs.get(attr))

    def get_uri(self):
        _uri_path = []
        for attr in self.uri_attrs:
            _uri_path.extend([attr.capitalize(), getattr(self, attr)])
        return "{0}://{1}/{2}".format(self.scheme, "/".join(_uri_path),
                                      self.glance_id)

    def _parse_attrs(self, attrs_info):
        attrs_list = attrs_info.strip('/').split('/')
        self.glance_id = attrs_list.pop()
        try:
            attrs_dict = {
                attrs_list[i].lower(): attrs_list[i + 1]
                for i in range(0, len(attrs_list), 2)
            }
        except IndexError:
            raise exceptions.BadStoreUri(
                message="Image URI should contain required attributes")

        if self._sorted_uri_attrs != sorted(attrs_dict.keys()):
            raise exceptions.BadStoreUri(
                message="Image URI should contain required attributes")
        for k, v in attrs_dict.items():
            setattr(self, k, v)

    def parse_uri(self, uri):
        """Parse URLs based on Azure scheme """
        LOG.debug('Parse uri %s' % (uri, ))
        if not uri.startswith('%s://' % STORE_SCHEME):
            reason = (_("URI %(uri)s must start with %(scheme)s://") % {
                'uri': uri,
                'scheme': STORE_SCHEME
            })
            LOG.error(reason)
            raise exceptions.BadStoreUri(message=reason)
        pieces = urllib.parse.urlparse(uri)
        self.scheme = pieces.scheme
        self._parse_attrs(pieces.netloc + pieces.path)


class Store(driver.Store):
    """An implementation of the Azure Backend Adapter"""

    _CAPABILITIES = (capabilities.BitMasks.RW_ACCESS |
                     capabilities.BitMasks.DRIVER_REUSABLE)

    def __init__(self, conf):
        super(Store, self).__init__(conf)
        self.scheme = STORE_SCHEME
        conf.register_group(config.azure_group)
        conf.register_opts(config.azure_opts, group=config.azure_group)

        self.tenant_id = conf.azure.tenant_id
        self.client_id = conf.azure.client_id
        self.client_secret = conf.azure.client_secret
        self.subscription_id = conf.azure.subscription_id
        self.resource_group = conf.azure.resource_group
        self.region = conf.azure.region
        self._azure_client = None

        LOG.info('Initialized Azure Glance Store driver')

    def get_schemes(self):
        return (STORE_SCHEME, )

    @property
    def azure_client(self):
        if self._azure_client is None:
            self._azure_client = utils.get_compute_client(
                self.tenant_id, self.client_id, self.client_secret,
                self.subscription_id)
            self._create_resource_group_if_not_created()
        return self._azure_client

    def _create_resource_group_if_not_created(self):
        resource_client = utils.get_resource_client(
            self.tenant_id, self.client_id, self.client_secret,
            self.subscription_id)
        is_resource_created = utils.check_resource_existence(
            resource_client, self.resource_group)
        if not is_resource_created:
            utils.create_resource_group(
                resource_client, self.resource_group, self.region)

    @capabilities.check
    def get(self, location, offset=0, chunk_size=None, context=None):
        """Takes a `glance_store.location.Location` object that indicates
        where to find the image file, and returns a tuple of generator
        (for reading the image file) and image_size
        :param location `glance_store.location.Location` object, supplied
                        from glance_store.location.get_location_from_uri()
        """
        return '%s://generic' % self.scheme, self.get_size(location, context)

    def get_size(self, location, context=None):
        image_name = location.store_location.images.split("/")[-1]
        response = utils.get_image(self.azure_client, self.resource_group,
                                   image_name)
        size = response.storage_profile.os_disk.disk_size_gb
        if size is None:
            return 1
        return size * units.Gi

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
        # This method works for Azure public images as we just need to delete
        # entry from glance catalog.
        # For Private images we will need extra handling here.
        LOG.info("Delete image %s" % location.get_store_uri())
