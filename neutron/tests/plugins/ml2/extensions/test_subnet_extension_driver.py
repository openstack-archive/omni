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
import json

import mock
from moto import mock_ec2

from neutron_lib import context
from neutron_lib.plugins import directory

from neutron.plugins.ml2 import config
from neutron.tests.common import aws_mock
from neutron.tests.unit.plugins.ml2 import test_plugin


class SubnetAzExtensionTestCase(test_plugin.Ml2PluginV2TestCase):
    """Subnet AZ Test case class."""

    _extension_drivers = ['subnet_az']

    def setUp(self):
        """Setup test case."""
        config.cfg.CONF.set_override('extension_drivers',
                                     self._extension_drivers,
                                     group='ml2')
        super(SubnetAzExtensionTestCase, self).setUp()
        self.mock_get_credentials = mock.patch(
            'neutron.common.aws_utils.get_credentials_using_credsmgr'
        ).start()
        self.mock_get_credentials.side_effect = aws_mock.fake_get_credentials

    def _create_subnet(self, network, **kwargs):
        data = {'subnet': {'network_id': network['network']['id'],
                           'ip_version': 4,
                           'tenant_id': network['network']['tenant_id'],
                           'cidr': kwargs['cidr'],
                           'availability_zone': kwargs['availability_zone']}}
        subnet_req = self.new_create_request('subnets', data, self.fmt)
        subnet_res = subnet_req.get_response(self.api)
        return subnet_res

    @mock_ec2
    @mock.patch("neutron.common.aws_utils.AwsUtils.get_keystone_session")
    def test_create_subnet_with_az(self, mock_get):
        """Test creating subnet with valid AZ."""
        mock_get.side_effect = aws_mock.FakeSession
        with self.network() as network:
            resp = self._create_subnet(
                network, cidr="192.168.1.0/16", availability_zone="us-east-1c")
            self.assertEqual(resp._status, '201 Created')
            subnet_resp = json.loads(resp._app_iter[0])
            self.assertTrue("availability_zone" in subnet_resp['subnet'])
            self.assertEqual(subnet_resp['subnet']['availability_zone'],
                             'us-east-1c')

    @mock_ec2
    @mock.patch("neutron.common.aws_utils.AwsUtils.get_keystone_session")
    def test_get_subnet_with_az(self, mock_get):
        """Test GET operation with AZ."""
        mock_get.side_effect = aws_mock.FakeSession
        with self.network() as network:
            resp = self._create_subnet(
                network, cidr="192.168.1.0/16", availability_zone="us-east-1c")
            self.assertEqual(resp._status, '201 Created')
            subnet_resp = json.loads(resp._app_iter[0])
            ctx = context.Context('', '', is_admin=True)
            subnet_data = directory.get_plugin().get_subnet(
                ctx, subnet_resp['subnet']['id'])
            self.assertEqual(subnet_data['availability_zone'], "us-east-1c")
