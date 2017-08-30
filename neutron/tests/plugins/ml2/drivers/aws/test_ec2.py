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
from neutron.common.aws_utils import AwsException
from neutron.common.aws_utils import cfg
from neutron.plugins.ml2.drivers.aws.mechanism_aws import AwsMechanismDriver
from neutron.tests import base


class AwsNeutronTestCase(base.BaseTestCase):
    @mock_ec2
    def setUp(self):
        super(AwsNeutronTestCase, self).setUp()
        cfg.CONF.AWS.region_name = 'us-east-1'
        cfg.CONF.AWS.access_key = 'aws_access_key'
        cfg.CONF.AWS.secret_key = 'aws_secret_key'
        cfg.CONF.AWS.az = 'us-east-1a'

        self._driver = AwsMechanismDriver()
        self.context = self.get_fake_context()
        self._driver.initialize()

    def get_fake_context(self):
        context = mock.Mock()
        context.current = {}
        context.network.current = {}
        context.current['name'] = "fake_name"
        context.current['id'] = "fake_id"
        context.current['cidr'] = "192.168.1.0/24"
        context.current['network_id'] = "fake_network_id"
        context.current['ip_version'] = 4
        context.current['tenant_id'] = "fake_tenant_id"
        context.network.current['id'] = "fake_id"
        context.network.current['name'] = "fake_name"
        context.current['subnets'] = {}
        return context

    @mock_ec2
    def test_update_network_success(self):
        self.assertIsNone(self._driver.update_network_precommit(self.context))

    @mock_ec2
    @mock.patch(
        'neutron.common.aws_utils.AwsUtils.get_vpc_from_neutron_network_id')
    def test_update_network_failure(self, mock_get):
        mock_get.return_value = "fake_vpc_id"
        self.assertRaises(AwsException, self._driver.update_network_precommit,
                          self.context)
        self.assertTrue(mock_get.called)
        mock_get.assert_called_once_with(self.context.current['id'])

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
    @mock.patch(
        'neutron.common.aws_utils.AwsUtils.get_vpc_from_neutron_network_id')
    def test_delete_network_failure(self, mock_get):
        self.context.current['subnets']['name'] = "fake_subnet_name"
        mock_get.return_value = "fake_vpc_id"
        self.assertRaises(AwsException, self._driver.delete_network_precommit,
                          self.context)
        self.assertTrue(mock_get.called)
        mock_get.assert_called_once_with(self.context.current['id'])

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
    def test_create_subnet_success(self):
        self.assertIsNone(self._driver.create_subnet_precommit(self.context))

    @mock_ec2
    def test_update_subnet_success(self):
        self._driver.create_subnet_precommit(self.context)
        self.assertIsNone(self._driver.update_subnet_precommit(self.context))

    @mock_ec2
    def test_update_subnet_failure(self):
        self.assertRaises(AwsException, self._driver.update_subnet_precommit,
                          self.context)

    @mock_ec2
    def test_delete_subnet_success(self):
        self.assertIsNone(self._driver.delete_subnet_precommit(self.context))

    @mock_ec2
    @mock.patch(
        'neutron.common.aws_utils.AwsUtils.get_subnet_from_neutron_subnet_id')
    def test_delete_subnet_failure(self, mock_get):
        mock_get.return_value = "fake_subnet_id"
        self.assertRaises(AwsException, self._driver.delete_subnet_precommit,
                          self.context)
        self.assertTrue(mock_get.called)
        mock_get.assert_called_once_with(self.context.current['id'])
