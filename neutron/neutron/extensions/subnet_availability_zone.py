"""
Copyright 2018 Platform9 Systems Inc.(http://www.platform9.com).

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

from neutron_lib.api import extensions

from neutron.extensions import availability_zone as az_ext

EXTENDED_ATTRIBUTES_2_0 = {
    'subnets': {
        az_ext.RESOURCE_NAME: {
            'allow_post': True, 'allow_put': False, 'is_visible': True,
            'default': None}},
}


class Subnet_availability_zone(extensions.ExtensionDescriptor):
    """Subnet availability zone extension."""

    @classmethod
    def get_name(cls):
        """Get name of extension."""
        return "Subnet Availability Zone"

    @classmethod
    def get_alias(cls):
        """Get alias of extension."""
        return "subnet_availability_zone"

    @classmethod
    def get_description(cls):
        """Get description of extension."""
        return "Availability zone support for subnet."

    @classmethod
    def get_updated(cls):
        """Get updated date of extension."""
        return "2018-08-10T10:00:00-00:00"

    def get_required_extensions(self):
        """Get list of required extensions."""
        return ["availability_zone"]

    def get_extended_resources(self, version):
        """Get extended resources for extension."""
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
