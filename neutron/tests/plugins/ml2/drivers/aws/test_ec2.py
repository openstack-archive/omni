"""
Copyright 2016 Platform9 Systems Inc.(http://www.platform9.com)
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

import mock

from moto import mock_ec2
from neutron.common.aws_utils import aws_conf
from neutron.common.aws_utils import AwsException
from neutron.plugins.ml2.drivers.aws.mechanism_aws import AwsMechanismDriver
from neutron.plugins.ml2.drivers.aws.mechanism_aws import AzNotProvided
from neutron.plugins.ml2.drivers.aws.mechanism_aws import InvalidAzValue
from neutron.plugins.ml2.drivers.aws.mechanism_aws import \
    NetworkWithMultipleAZs
from neutron.tests.common import aws_mock
from neutron.tests.unit import testlib_api

AWS_DRIVER = "neutron.plugins.ml2.drivers.aws.mechanism_aws.AwsMechanismDriver"


class AwsNeutronTestCase(testlib_api.SqlTestCase):
    @mock_ec2
    def setUp(self):
        super(AwsNeutronTestCase, self).setUp()
        self.mock_get_credentials = mock.patch(
            'neutron.common.aws_utils.get_credentials_using_credsmgr'
        ).start()
        self.mock_get_credentials.side_effect = aws_mock.fake_get_credentials
        aws_conf.region_name = 'us-east-1'
        self._driver = AwsMechanismDriver()
        self.context = aws_mock.get_fake_context()
        self._driver.initialize()

    @mock_ec2
    def test_update_network_success(self):
        self.assertIsNone(self._driver.update_network_precommit(self.context))

    @mock_ec2
    @mock.patch(
        'neutron.common.aws_utils.AwsUtils.get_vpc_from_neutron_network_id')
    def test_update_network_failure(self, mock_get):
        mock_get.return_value = "vpc-00000000"
        self.assertRaises(AwsException, self._driver.update_network_precommit,
                          self.context)
        self.assertTrue(mock_get.called)
        mock_get.assert_called_once_with(
            self.context.current['id'], self.context._plugin_context,
            project_id=self.context.current['project_id'])

    @mock_ec2
    def test_delete_network_with_no_subnets(self):
        self.assertIsNone(self._driver.delete_network_precommit(self.context))

    @mock_ec2
    def test_delete_network_without_vpc(self):
        self.context.current['subnets']['name'] = "fake_subnet_name"
        self.assertIsNone(self._driver.delete_network_precommit(self.context))

    @mock_ec2
    def test_delete_network_success(self):
        self.context.current['subnets']['name'] = "fake_subnet_name"
        self.assertIsNone(self._driver.delete_network_precommit(self.context))

    @mock_ec2
    def test_create_subnet_with_external_network(self):
        self.context.network.current[
            'provider:physical_network'] = "external"
        self.assertIsNone(self._driver.create_subnet_precommit(self.context))
        del self.context.network.current['provider:physical_network']

    @mock_ec2
    def test_create_subnet_with_invalid_ipversion(self):
        self.context.current['ip_version'] = 6
        self.assertRaises(AwsException, self._driver.create_subnet_precommit,
                          self.context)
        self.context.current['ip_version'] = 4

    @mock_ec2
    @mock.patch(AWS_DRIVER + "._send_request")
    @mock.patch("neutron.common.aws_utils.AwsUtils.get_keystone_session")
    def test_create_subnet_success(self, mock_get, mock_send):
        mock_get.side_effect = aws_mock.FakeSession
        mock_send.return_value = aws_mock.mock_send_value
        self.assertIsNone(self._driver.create_subnet_precommit(self.context))

    @mock_ec2
    @mock.patch(AWS_DRIVER + "._send_request")
    @mock.patch("neutron.common.aws_utils.AwsUtils.get_keystone_session")
    def test_update_subnet_success(self, mock_get, mock_send):
        mock_get.side_effect = aws_mock.FakeSession
        mock_send.return_value = aws_mock.mock_send_value
        self._driver.create_subnet_precommit(self.context)
        self.assertIsNone(self._driver.update_subnet_precommit(self.context))

    @mock_ec2
    def test_update_subnet_failure(self):
        self.assertRaises(AwsException, self._driver.update_subnet_precommit,
                          self.context)

    @mock_ec2
    def test_create_subnet_with_multiple_az_on_network(self):
        """Test create subnet with multiple AZs on network."""
        self.context.network.current['availability_zone_hints'].append(
            "us-east-1c")
        self.assertRaises(NetworkWithMultipleAZs,
                          self._driver.create_subnet_precommit, self.context)
        self.context.network.current['availability_zone_hints'].remove(
            "us-east-1c")

    @mock_ec2
    @mock.patch(
        "neutron.common.aws_utils.AwsUtils.get_subnet_from_neutron_subnet_id")
    def test_delete_subnet_success(self, mock_get_subnet):
        mock_get_subnet.side_effect = self.context.current['id']
        self.assertIsNone(self._driver.delete_subnet_precommit(self.context))
        mock_get_subnet.assert_called_once_with(
            self.context.current['id'], context=self.context._plugin_context,
            project_id=self.context.current['project_id'])

    @mock_ec2
    @mock.patch(AWS_DRIVER + "._send_request")
    @mock.patch("neutron.common.aws_utils.AwsUtils.get_keystone_session")
    def test_create_subnet_with_invalid_az(self, mock_get, mock_send):
        """Test create operation with invalid AZ."""
        mock_get.side_effect = aws_mock.FakeSession
        mock_send.return_value = aws_mock.mock_send_value
        self.context.current['availability_zone'] = "invalid_az"
        self.assertRaises(InvalidAzValue, self._driver.create_subnet_precommit,
                          self.context)

    @mock_ec2
    @mock.patch("neutron.common.aws_utils.AwsUtils.get_keystone_session")
    def test_create_subnet_with_no_az_on_network(self, mock_get):
        """Test create operation with no AZ."""
        mock_get.side_effect = aws_mock.FakeSession
        self.context.network.current['availability_zone_hints'] = []
        self.assertRaises(AzNotProvided, self._driver.create_subnet_precommit,
                          self.context)
        self.context.network.current['availability_zone_hints'] = \
            ['us-east-1a']

    @mock_ec2
    @mock.patch("neutron.common.aws_utils.AwsUtils.get_keystone_session")
    def test_create_subnet_with_multiple_az(self, mock_get):
        """Test create operation with multiple AZ in subnet."""
        mock_get.side_effect = aws_mock.FakeSession
        self.context.current['availability_zone'] = "us-east-1a,us-east-1c"
        self.assertRaises(
            NetworkWithMultipleAZs, self._driver.create_subnet_precommit,
            self.context)
