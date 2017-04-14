# Copyright (c) 2017 Platform9 Systems Inc. (http://www.platform9.com)
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import logging

import gceutils
import glance_store.driver
import glance_store.location
from glance_store import capabilities, exceptions
from glance_store.i18n import _
from oslo_config import cfg
from oslo_utils import units
from six.moves import urllib

LOG = logging.getLogger(__name__)

MAX_REDIRECTS = 5
STORE_SCHEME = 'gce'

gce_group = cfg.OptGroup(name='GCE',
                         title='Options to connect to Google cloud')

gce_opts = [
    cfg.StrOpt('service_key_path', help='Service key of GCE account',
               secret=True),
    cfg.StrOpt('zone', help='GCE region'),
    cfg.StrOpt('project_id', help='GCE project id'),
]


class StoreLocation(glance_store.location.StoreLocation):
    """Class describing GCE URI."""

    def __init__(self, store_specs, conf):
        super(StoreLocation, self).__init__(store_specs, conf)

    def process_specs(self):
        self.scheme = self.specs.get('scheme', STORE_SCHEME)
        self.gce_project = self.specs.get('gce_project')
        self.gce_id = self.specs.get('gce_id')
        self.glance_id = self.specs.get('glance_id')

    def get_uri(self):
        return "{0}://{1}/{2}/{3}".format(self.scheme, self.gce_project,
                                          self.gce_id, self.glance_id)

    def parse_uri(self, uri):
        """Parse URLs based on GCE scheme """
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
        gce_project = pieces.netloc
        gce_id, glance_id = pieces.path.strip('/').split('/')
        parse_params = (gce_project, gce_id, glance_id)
        if not all([parse_params]):
            raise exceptions.BadStoreUri(uri=uri)
        self.gce_project, self.gce_id, self.glance_id = parse_params


class Store(glance_store.driver.Store):
    """An implementation of the HTTP(S) Backend Adapter"""

    _CAPABILITIES = (capabilities.BitMasks.RW_ACCESS |
                     capabilities.BitMasks.DRIVER_REUSABLE)

    def __init__(self, conf):
        super(Store, self).__init__(conf)
        conf.register_group(gce_group)
        conf.register_opts(gce_opts, group=gce_group)
        self.gce_zone = conf.GCE.zone
        self.gce_project = conf.GCE.project_id
        self.gce_svc_key = conf.GCE.service_key_path
        self.gce_svc = gceutils.get_gce_service(self.gce_svc_key)
        LOG.info('Initialized GCE Glance Store driver')

    def get_schemes(self):
        """
        :retval tuple: containing valid scheme names to
                associate with this store driver
        """
        return ('gce', )

    @capabilities.check
    def get(self, location, offset=0, chunk_size=None, context=None):
        """
        Takes a `glance_store.location.Location` object that indicates
        where to find the image file, and returns a tuple of generator
        (for reading the image file) and image_size

        :param location `glance_store.location.Location` object, supplied
                        from glance_store.location.get_location_from_uri()
        """
        yield ('gce://generic', self.get_size(location, context))

    def get_size(self, location, context=None):
        """
        Takes a `glance_store.location.Location` object that indicates
        where to find the image file, and returns the size

        :param location `glance_store.location.Location` object, supplied
                        from glance_store.location.get_location_from_uri()
        :retval int: size of image file in bytes
        """
        img_data = gceutils.get_image(self.gce_svc,
                                      location.store_location.gce_project,
                                      location.store_location.gce_id)
        img_size = int(img_data['diskSizeGb']) * units.Gi
        return img_size

    @capabilities.check
    def add(self, image_id, image_file, image_size, context=None,
            verifier=None):
        """
        Stores an image file with supplied identifier to the backend
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
        raise NotImplementedError

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
