"""
Copyright (c) 2016 Platform9 Systems Inc. (http://www.platform9.com)
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
import hashlib
import logging
import uuid

import glance.registry.client.v1.api as registry
from glance_store import capabilities
import glance_store.driver
from glance_store import exceptions
from glance_store.i18n import _
import glance_store.location
from oslo_config import cfg
from oslo_utils import units
from six.moves import urllib

import boto3
import botocore.exceptions

from glance_store._drivers import awsutils

LOG = logging.getLogger(__name__)

MAX_REDIRECTS = 5
STORE_SCHEME = 'aws'

aws_opts_group = cfg.OptGroup(name='aws', title='AWS specific options')
aws_opts = [cfg.StrOpt('access_key', help='AWS access key ID'),
            cfg.StrOpt('secret_key', help='AWS secret access key'),
            cfg.StrOpt('region_name', help='AWS region name')]

keystone_opts_group = cfg.OptGroup(
    name='keystone_credentials', title='Keystone credentials')

keystone_opts = [cfg.StrOpt('region_name', help='Keystone region name'), ]


def _get_image_uuid(ami_id):
    md = hashlib.md5()
    md.update(ami_id)
    return str(uuid.UUID(bytes=md.digest()))


class StoreLocation(glance_store.location.StoreLocation):

    """Class describing an AWS URI."""

    def __init__(self, store_specs, conf):
        super(StoreLocation, self).__init__(store_specs, conf)

    def process_specs(self):
        self.scheme = self.specs.get('scheme', STORE_SCHEME)
        self.ami_id = self.specs.get('ami_id')

    def get_uri(self):
        return "{}://{}".format(self.scheme, self.ami_id)

    def parse_uri(self, uri):
        """
        Parse URLs. This method fixes an issue where credentials specified
        in the URL are interpreted differently in Python 2.6.1+ than prior
        versions of Python.
        """
        if not uri.startswith('%s://' % STORE_SCHEME):
            reason = (_("URI %(uri)s must start with %(scheme)s://") %
                      {'uri': uri, 'scheme': STORE_SCHEME})
            LOG.info(reason)
            raise exceptions.BadStoreUri(message=reason)
        pieces = urllib.parse.urlparse(uri)
        self.scheme = pieces.scheme
        ami_id = pieces.netloc
        if ami_id == '':
            LOG.info(_("No image ami_id specified in URL"))
            raise exceptions.BadStoreUri(uri=uri)
        self.ami_id = ami_id
        self.image_id = pieces.path.strip('/')


class Store(glance_store.driver.Store):

    """An implementation of the HTTP(S) Backend Adapter"""

    _CAPABILITIES = (capabilities.BitMasks.RW_ACCESS |
                     capabilities.BitMasks.DRIVER_REUSABLE)

    def __init__(self, conf):
        super(Store, self).__init__(conf)
        conf.register_group(aws_opts_group)
        conf.register_opts(aws_opts, group=aws_opts_group)
        conf.register_group(keystone_opts_group)
        conf.register_opts(keystone_opts, group=keystone_opts_group)
        self.conf = conf
        self.region_name = conf.aws.region_name

    def _get_ec2_client(self, context, tenant):
        creds = awsutils.get_credentials(context, tenant, conf=self.conf)
        creds['region_name'] = self.region_name
        return boto3.client('ec2', **creds)

    def _get_ec2_resource(self, context, tenant):
        creds = awsutils.get_credentials(context, tenant, conf=self.conf)
        creds['region_name'] = self.region_name
        return boto3.resource('ec2', **creds)

    @capabilities.check
    def get(self, location, offset=0, chunk_size=None, context=None):
        """
        Takes a `glance_store.location.Location` object that indicates
        where to find the image file, and returns a tuple of generator
        (for reading the image file) and image_size

        :param location `glance_store.location.Location` object, supplied
                        from glance_store.location.get_location_from_uri()
        """
        return 'aws://generic', self.get_size(location, context)

    @capabilities.check
    def delete(self, location, context=None):
        """Takes a `glance_store.location.Location` object that indicates
        where to find the image file to delete

        :param location: `glance_store.location.Location` object, supplied
                  from glance_store.location.get_location_from_uri()
        :raises NotFound if image does not exist
        """
        ami_id = location.store_location.ami_id
        image_id = location.store_location.image_id
        image_info = registry.get_image_metadata(context, image_id)
        project_id = image_info['owner']
        aws_client = self._get_ec2_client(context, project_id)
        aws_imgs = aws_client.describe_images(Owners=['self'])['Images']
        for img in aws_imgs:
            if ami_id == img.get('ImageId'):
                LOG.warn('**** ID of ami being deleted: {}'.format(ami_id))
                aws_client.deregister_image(ImageId=ami_id)

    def get_schemes(self):
        """
        :retval tuple: containing valid scheme names to
                associate with this store driver
        """
        return ('aws',)

    def _get_size_from_properties(self, image_info):
        """
        :param image_info dict object, supplied from
                          registry.get_image_metadata
        :retval int: size of image in bytes or -1 if size could not be fetched
                     from image properties alone
        """
        img_size = -1
        if 'properties' in image_info:
            img_props = image_info['properties']
            if img_props.get('aws_root_device_type') == 'ebs' and \
                    'aws_ebs_vol_sizes' in img_props:
                ebs_vol_size_str = img_props['aws_ebs_vol_sizes']
                img_size = 0
                # sizes are stored as string - "[8, 16]"
                # Convert it to array of int
                ebs_vol_sizes = [int(vol.strip()) for vol in
                                 ebs_vol_size_str.replace('[', '').
                                 replace(']', '').split(',')]
                for vol_size in ebs_vol_sizes:
                    img_size += vol_size
            elif img_props.get('aws_root_device_type') != 'ebs':
                istore_vols = int(img_props.get('aws_num_istore_vols', '0'))
                if istore_vols >= 1:
                    img_size = 0
        return img_size

    def get_size(self, location, context=None):
        """
        Takes a `glance_store.location.Location` object that indicates
        where to find the image file, and returns the size

        :param location `glance_store.location.Location` object, supplied
                        from glance_store.location.get_location_from_uri()
        :retval int: size of image file in bytes
        """
        ami_id = location.store_location.ami_id
        image_id = location.store_location.image_id
        image_info = registry.get_image_metadata(context, image_id)
        project_id = image_info['owner']
        ec2_resource = self._get_ec2_resource(context, project_id)
        image = ec2_resource.Image(ami_id)
        size = self._get_size_from_properties(image_info)
        if size >= 0:
            LOG.debug('Got image size from properties as %d' % size)
            # Convert size in gb to bytes
            size *= units.Gi
            return size
        try:
            image.load()
            # no size info for instance-store volumes, so return 1 in that case
            # Setting size as 0 fails multiple checks in glance required for
            # successful creation of image record.
            size = 1
            if image.root_device_type == 'ebs':
                for bdm in image.block_device_mappings:
                    if 'Ebs' in bdm and 'VolumeSize' in bdm['Ebs']:
                        LOG.debug('ebs info: %s' % bdm['Ebs'])
                        size += bdm['Ebs']['VolumeSize']
                # convert size in gb to bytes
                size *= units.Gi
        except botocore.exceptions.ClientError as ce:
            if ce.response['Error']['Code'] == 'InvalidAMIID.NotFound':
                raise exceptions.ImageDataNotFound()
            else:
                raise exceptions.GlanceStoreException(
                    ce.response['Error']['Code'])
        return size
