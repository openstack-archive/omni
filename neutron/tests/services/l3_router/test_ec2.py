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

from moto import mock_ec2
from neutron.common.aws_utils import aws_conf
from neutron.common.aws_utils import AwsException
from neutron.common.aws_utils import AwsUtils
from neutron.common import exceptions
from neutron.services.l3_router.aws_router_plugin import AwsRouterPlugin
from neutron.services.l3_router.aws_router_plugin import \
    RouterIdInvalidException
from neutron.tests import base
from neutron.tests.unit.extensions import test_securitygroup as test_sg
from neutron_lib import constants as const

L3_NAT_DBONLY_MIXIN = 'neutron.db.l3_db.L3_NAT_dbonly_mixin'
L3_NAT_WITH_DVR_DB_MIXIN = 'neutron.db.l3_dvr_db.L3_NAT_with_dvr_db_mixin'
AWS_ROUTER = 'neutron.services.l3_router.aws_router_plugin.AwsRouterPlugin'


def fake_get_credentials(*args, **kwargs):
    return {
        'aws_access_key_id': 'fake_access_key_id',
        'aws_secret_access_key': 'fake_access_key'
    }


class AWSRouterPluginTests(test_sg.SecurityGroupsTestCase, base.BaseTestCase):
    @mock_ec2
    def setUp(self):
        super(AWSRouterPluginTests, self).setUp()
        self.mock_get_credentials = mock.patch(
            'neutron.common.aws_utils.get_credentials_using_credsmgr'
        ).start()
        self.mock_get_credentials.side_effect = fake_get_credentials
        aws_conf.secret_key = 'aws_access_key'
        aws_conf.access_key = 'aws_secret_key'
        aws_conf.region_name = 'us-east-1'
        self._driver = AwsRouterPlugin()
        self.context = self._create_fake_context()

    def _create_fake_context(self):
        context = mock.Mock()
        context.current = {}
        context.current['id'] = "fake_id_1234"
        context.current['cidr'] = "192.168.1.0/24"
        context.current['network_id'] = "fake_network_id_1234"

        context._plugin_context = {}
        context._plugin_context['tenant'] = "fake_tenant_id"
        context._plugin_context['auth_token'] = "fake_auth_token"
        return context

    def _get_fake_tags(self):
        tags = []
        tags.append({'Value': 'fake_name', 'Key': 'Name'})
        tags.append({'Value': 'fake_id', 'Key': 'openstack_network_id'})
        tags.append({'Value': 'fake_tenant_id', 'Key': 'openstack_tenant_id'})
        return tags

    def _create_router(self, mock_create):
        mock_create.return_value = {'id': 'fake_id'}
        router = {'router': {'name': 'fake_name'}}
        response = self._driver.create_router(self.context, router)
        mock_create.assert_called_once_with(self.context, router)
        return response

    @mock_ec2
    @mock.patch(L3_NAT_WITH_DVR_DB_MIXIN + '.create_floatingip')
    @mock.patch(AWS_ROUTER + '._associate_floatingip_to_port')
    def test_create_floatingip_with_port(self, mock_assoc, mock_create):
        floatingip = {'floatingip': {
            'port_id': 'fake_port_id',
            'floating_ip_address': None}}
        mock_assoc.return_value = None
        mock_create.return_value = None
        self.assertIsNone(self._driver.create_floatingip(self.context,
                                                         floatingip))
        self.assertTrue(mock_assoc.called)
        mock_create.assert_called_once_with(
            self.context, floatingip,
            initial_status=const.FLOATINGIP_STATUS_DOWN)

    @mock_ec2
    @mock.patch(L3_NAT_WITH_DVR_DB_MIXIN + '.create_floatingip')
    def test_create_floatingip_without_port(self, mock_create):
        floatingip = {'floatingip': {'floating_ip_address': None}}
        mock_create.return_value = None
        self.assertIsNone(self._driver.create_floatingip(self.context,
                                                         floatingip))
        mock_create.assert_called_once_with(
            self.context, floatingip,
            initial_status=const.FLOATINGIP_STATUS_DOWN)

    @mock_ec2
    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_port')
    def test_create_floatingip_with_failure_in_associating(self, mock_get):
        floatingip = {'floatingip': {
            'port_id': 'fake_port_id',
            'floating_ip_address': None}}
        port = {'fixed_ips': []}
        mock_get.return_value = port
        self.assertRaises(AwsException, self._driver.create_floatingip,
                          self.context, floatingip)

    @mock_ec2
    @mock.patch(L3_NAT_WITH_DVR_DB_MIXIN + '.create_floatingip')
    @mock.patch(AWS_ROUTER + '._associate_floatingip_to_port')
    def test_create_floatingip_with_failure_in_creating(
            self, mock_assoc, mock_create):
        floatingip = {'floatingip': {
            'port_id': 'fake_port_id',
            'floating_ip_address': None}}
        mock_create.side_effect = exceptions.PhysicalNetworkNameError()
        mock_assoc.return_value = None
        self.assertRaises(exceptions.PhysicalNetworkNameError,
                          self._driver.create_floatingip, self.context,
                          floatingip)

    @mock_ec2
    @mock.patch(L3_NAT_WITH_DVR_DB_MIXIN + '.update_floatingip')
    @mock.patch(L3_NAT_DBONLY_MIXIN + '.get_floatingip')
    def test_update_floatingip_without_port(self, mock_get, mock_update):
        fake_id = 'fake_id'
        floatingip = {'floatingip': {}}
        mock_get.return_value = {}
        mock_update.return_value = None
        self.assertIsNone(self._driver.update_floatingip(self.context, fake_id,
                                                         floatingip))
        self.assertTrue(mock_get.called)
        mock_get.assert_called_once_with(self.context, fake_id)
        mock_update.assert_called_once_with(self.context, fake_id, floatingip)

    @mock_ec2
    @mock.patch(L3_NAT_WITH_DVR_DB_MIXIN + '.delete_floatingip')
    @mock.patch(L3_NAT_DBONLY_MIXIN + '.get_floatingip')
    def test_delete_floatingip_success(self, mock_get, mock_delete):
        fake_id = 'fake_id'
        mock_get.return_value = {'floating_ip_address': '192.169.10.1',
                                 'project_id': 'fake_projectid'}
        mock_delete.return_value = None
        self.assertIsNone(self._driver.delete_floatingip(self.context,
                                                         fake_id))
        self.assertTrue(mock_get.called)
        mock_get.assert_called_once_with(self.context, fake_id)
        mock_delete.assert_called_once_with(self.context, fake_id)

    @mock_ec2
    @mock.patch(L3_NAT_WITH_DVR_DB_MIXIN + '.delete_floatingip')
    @mock.patch(L3_NAT_DBONLY_MIXIN + '.get_floatingip')
    def test_delete_floatingip_failure(self, mock_get, mock_delete):
        fake_id = 'fake_id'
        mock_get.return_value = {'floating_ip_address': '192.169.10.1',
                                 'project_id': 'fake_projectid'}
        mock_delete.side_effect = exceptions.PhysicalNetworkNameError()
        self.assertRaises(exceptions.PhysicalNetworkNameError,
                          self._driver.delete_floatingip,
                          self.context, fake_id)
        self.assertTrue(mock_get.called)
        mock_get.assert_called_once_with(self.context, fake_id)

    @mock_ec2
    @mock.patch(L3_NAT_WITH_DVR_DB_MIXIN + '.delete_floatingip')
    @mock.patch(L3_NAT_DBONLY_MIXIN + '.get_floatingip')
    def test_delete_floatingip_aws_failure(self, mock_get, mock_delete):
        fake_id = 'fake_id'
        mock_get.return_value = {'floating_ip_address': None,
                                 'project_id': 'fake_projectid'}
        mock_delete.side_effect = {}
        self.assertRaises(AwsException, self._driver.delete_floatingip,
                          self.context, fake_id)
        self.assertTrue(mock_get.called)
        mock_get.assert_called_once_with(self.context, fake_id)

    @mock_ec2
    @mock.patch(L3_NAT_WITH_DVR_DB_MIXIN + '.update_floatingip')
    @mock.patch(L3_NAT_DBONLY_MIXIN + '.get_floatingip')
    def test_update_floatingip_with_port(self, mock_get, mock_update):
        fake_id = 'fake_id'
        floatingip = {'floatingip': {'port_id': None}}
        mock_get.return_value = {'floating_ip_address': '192.169.10.1'}
        mock_update.return_value = None
        self.assertIsNone(self._driver.update_floatingip(self.context, fake_id,
                                                         floatingip))
        self.assertTrue(mock_get.called)
        mock_get.assert_called_once_with(self.context, fake_id)
        mock_update.assert_called_once_with(self.context, fake_id, floatingip)

    @mock_ec2
    @mock.patch(L3_NAT_WITH_DVR_DB_MIXIN + '.update_floatingip')
    @mock.patch(L3_NAT_DBONLY_MIXIN + '.get_floatingip')
    def test_update_floatingip_failure_without_port(self, mock_get,
                                                    mock_update):
        fake_id = 'fake_id'
        floatingip = {'floatingip': {}}
        mock_get.return_value = {'floating_ip_address': '192.169.10.1'}
        mock_update.side_effect = exceptions.PhysicalNetworkNameError()
        self.assertRaises(exceptions.PhysicalNetworkNameError,
                          self._driver.update_floatingip, self.context,
                          fake_id, floatingip)
        self.assertTrue(mock_get.called)
        mock_get.assert_called_once_with(self.context, fake_id)

    @mock_ec2
    @mock.patch(L3_NAT_WITH_DVR_DB_MIXIN + '.update_floatingip')
    @mock.patch(L3_NAT_DBONLY_MIXIN + '.get_floatingip')
    def test_update_floatingip_failure_with_port(self, mock_get, mock_update):
        fake_id = 'fake_id'
        floatingip = {'floatingip': {'port': 'fake_port_id'}}
        mock_get.return_value = {'floating_ip_address': '192.169.10.1'}
        mock_update.side_effect = exceptions.PhysicalNetworkNameError()
        self.assertRaises(exceptions.PhysicalNetworkNameError,
                          self._driver.update_floatingip, self.context,
                          fake_id, floatingip)
        self.assertTrue(mock_get.called)
        mock_get.assert_called_once_with(self.context, fake_id)

    @mock_ec2
    @mock.patch(L3_NAT_DBONLY_MIXIN + '.create_router')
    def test_create_router_success(self, mock_create):
        response = self._create_router(mock_create)
        self.assertIsInstance(response, dict)

    @mock_ec2
    @mock.patch(L3_NAT_DBONLY_MIXIN + '.create_router')
    def test_create_router_failure(self, mock_create):
        mock_create.side_effect = exceptions.PhysicalNetworkNameError()
        router = {'router': {'name': 'fake_name'}}
        self.assertRaises(exceptions.PhysicalNetworkNameError,
                          self._driver.create_router, self.context, router)

    @mock_ec2
    @mock.patch('neutron.db.l3_hamode_db.L3_HA_NAT_db_mixin.delete_router')
    @mock.patch(L3_NAT_DBONLY_MIXIN + '.create_router')
    @mock.patch(L3_NAT_DBONLY_MIXIN + '._get_router')
    def test_delete_router_success(self, mock_get, mock_create, mock_delete):
        mock_get.return_value = {'name': 'test_router',
                                 'project_id': 'fake_project'}
        mock_delete.return_value = None
        response = self._create_router(mock_create)
        self.assertIsNone(self._driver.delete_router(self.context,
                                                     response['id']))
        self.assertTrue(mock_delete.called)
        mock_delete.assert_called_once_with(self.context, response['id'])

    @mock_ec2
    @mock.patch('neutron.db.l3_hamode_db.L3_HA_NAT_db_mixin.delete_router')
    @mock.patch(L3_NAT_DBONLY_MIXIN + '.create_router')
    @mock.patch(L3_NAT_DBONLY_MIXIN + '._get_router')
    @mock.patch('neutron.db.omni_resources.get_omni_resource')
    def test_delete_router_resource_not_found(
            self, mock_get_omni_resource, mock_get, mock_create, mock_delete):
        mock_get_omni_resource.return_value = None
        mock_get.return_value = {'name': 'test_router',
                                 'project_id': 'fake_project'}
        mock_delete.return_value = None
        response = self._create_router(mock_create)
        self.assertRaises(RouterIdInvalidException, self._driver.delete_router,
                          self.context, response['id'])

    @mock_ec2
    @mock.patch(L3_NAT_WITH_DVR_DB_MIXIN + '.delete_router')
    @mock.patch(L3_NAT_DBONLY_MIXIN + '.create_router')
    @mock.patch(L3_NAT_DBONLY_MIXIN + '._get_router')
    def test_delete_router_failure(self, mock_get, mock_create, mock_delete):
        mock_get.return_value = {'name': 'test_router',
                                 'project_id': 'fake_project'}
        mock_delete.side_effect = exceptions.PhysicalNetworkNameError()
        response = self._create_router(mock_create)
        self.assertRaises(
            exceptions.PhysicalNetworkNameError, self._driver.delete_router,
            self.context, response['id'])

    @mock_ec2
    @mock.patch(
        'neutron.db.extraroute_db.ExtraRoute_dbonly_mixin.update_router')
    @mock.patch(L3_NAT_DBONLY_MIXIN + '.create_router')
    @mock.patch(L3_NAT_DBONLY_MIXIN + '._get_router')
    def test_update_router_success(self, mock_get, mock_create, mock_update):
        mock_get.return_value = {'name': 'test_router',
                                 'project_id': 'fake_project'}
        mock_update.return_value = {'id': "fake_id"}
        response = self._create_router(mock_create)
        router = {'router': {'name': 'fake_name'}}
        response = self._driver.update_router(
            self.context, response['id'], router)
        self.assertIsInstance(response, dict)
        mock_update.assert_called_once_with(
            self.context, response['id'], router)

    @mock_ec2
    @mock.patch(L3_NAT_WITH_DVR_DB_MIXIN + '.add_router_interface')
    @mock.patch(
        'neutron.common.aws_utils.AwsUtils.get_vpc_from_neutron_network_id')
    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_subnet')
    @mock.patch(L3_NAT_DBONLY_MIXIN + '.create_router')
    @mock.patch(L3_NAT_DBONLY_MIXIN + '._get_router')
    def test_add_router_interface(self, mock_get_router, mock_create, mock_get,
                                  mock_vpc, mock_add):
        aws_obj = AwsUtils()
        vpc_id = aws_obj.create_vpc_and_tags(self.context.current['cidr'],
                                             self._get_fake_tags(),
                                             self.context._plugin_context)
        interface_info = {'subnet_id': '00000000-0000-0000-0000-000000000000'}
        response = self._create_router(mock_create)
        router_id = response['id']
        mock_get.return_value = {'network_id': 'fake_network_id'}
        # We need to mock 'get_vpc_from_neutron_network_id' from aws_utils,
        # because we need a valid vpc_id when attaching internet gateway.
        mock_vpc.return_value = vpc_id
        mock_add.return_value = {'id': 'fake_id',
                                 'subnet_id': 'fake_subnet_id'}
        mock_get_router.return_value = {'name': 'test_router'}
        response = self._driver.add_router_interface(
            self.context, router_id, interface_info)
        self.assertIsInstance(response, dict)
        mock_add.assert_called_once_with(self.context, router_id,
                                         interface_info)

    @mock_ec2
    @mock.patch(L3_NAT_WITH_DVR_DB_MIXIN + '.remove_router_interface')
    @mock.patch(L3_NAT_DBONLY_MIXIN + '.create_router')
    @mock.patch(L3_NAT_DBONLY_MIXIN + '._get_router')
    def test_remove_router_interface(self, mock_get_router, mock_create,
                                     mock_remove):
        mock_get_router.return_value = {'project_id': 'fake_project_id'}
        response = self._create_router(mock_create)
        router_id = response['id']
        interface_info = {'port_id': 'fake_port_id'}
        mock_remove.return_value = {'id': 'fake_id',
                                    'subnet_id': 'fake_subnet_id'}
        response = self._driver.remove_router_interface(
            self.context, router_id, interface_info)
        self.assertIsInstance(response, dict)
        mock_remove.assert_called_once_with(self.context, router_id,
                                            interface_info)
