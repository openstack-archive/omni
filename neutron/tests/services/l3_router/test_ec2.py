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

from neutron.common.aws_utils import cfg
from neutron.common.aws_utils import AwsException
from neutron.common import exceptions
from neutron_lib import constants as const
from neutron.services.l3_router.aws_router_plugin import AwsRouterPlugin
from neutron.tests import base
from neutron.tests.unit.extensions import test_securitygroup as test_sg
from moto import mock_ec2

L3_NAT_DBONLY_MIXIN = 'neutron.db.l3_db.L3_NAT_dbonly_mixin'
L3_NAT_WITH_DVR_DB_MIXIN = 'neutron.db.l3_dvr_db.L3_NAT_with_dvr_db_mixin'
AWS_ROUTER = 'neutron.services.l3_router.aws_router_plugin.AwsRouterPlugin'
AWS_UTILS = 'neutron.common.aws_utils.AwsUtils'


class FakeInternetGateway(object):
    def create_tags(*args, **kwargs):
        pass


class AWSRouterPluginTests(test_sg.SecurityGroupsTestCase, base.BaseTestCase):
    @mock_ec2
    def setUp(self):
        super(AWSRouterPluginTests, self).setUp()
        cfg.CONF.AWS.secret_key = 'aws_access_key'
        cfg.CONF.AWS.access_key = 'aws_secret_key'
        cfg.CONF.AWS.region_name = 'us-east-1'
        self._driver = AwsRouterPlugin()
        self.context = self._create_fake_context()

    def _create_fake_context(self):
        context = mock.Mock()
        context.current = {}
        context.current['id'] = "fake_id_1234"
        context.current['cidr'] = "192.168.1.0/24"
        context.current['network_id'] = "fake_network_id_1234"
        return context

    @mock_ec2
    @mock.patch(L3_NAT_WITH_DVR_DB_MIXIN + '.create_floatingip')
    @mock.patch(AWS_ROUTER + '._associate_floatingip_to_port')
    @mock.patch(AWS_UTILS + '.allocate_elastic_ip')
    def test_create_floatingip_with_port(self, mock_allocate, mock_assoc,
                                         mock_create):
        floatingip = {'floatingip': {'port_id': 'fake_port_id'}}
        mock_allocate.return_value = {'PublicIp': '192.169.10.1'}
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
    @mock.patch(AWS_ROUTER + '._associate_floatingip_to_port')
    @mock.patch(AWS_UTILS + '.allocate_elastic_ip')
    def test_create_floatingip_without_port(self, mock_allocate, mock_assoc,
                                            mock_create):
        floatingip = {'floatingip': {}}
        mock_allocate.return_value = {'PublicIp': '192.169.10.1'}
        mock_assoc.return_value = None
        mock_create.return_value = None
        self.assertIsNone(self._driver.create_floatingip(self.context,
                                                         floatingip))
        self.assertFalse(mock_assoc.called)
        mock_create.assert_called_once_with(
            self.context, floatingip,
            initial_status=const.FLOATINGIP_STATUS_DOWN)

    @mock_ec2
    @mock.patch(AWS_UTILS + '.delete_elastic_ip')
    @mock.patch(AWS_ROUTER + '._associate_floatingip_to_port')
    @mock.patch(AWS_UTILS + '.allocate_elastic_ip')
    def test_create_floatingip_with_failure_in_associating(
            self, mock_allocate, mock_assoc, mock_delete):
        floatingip = {'floatingip': {'port_id': 'fake_port_id'}}
        mock_allocate.return_value = {'PublicIp': '192.169.10.1'}
        mock_assoc.side_effect = exceptions.PhysicalNetworkNameError()
        mock_delete.return_value = {}
        self.assertRaises(exceptions.PhysicalNetworkNameError,
                          self._driver.create_floatingip, self.context,
                          floatingip)
        self.assertTrue(mock_assoc.called)
        self.assertTrue(mock_delete.called)

    @mock_ec2
    @mock.patch(AWS_UTILS + '.delete_elastic_ip')
    @mock.patch(L3_NAT_WITH_DVR_DB_MIXIN + '.create_floatingip')
    @mock.patch(AWS_ROUTER + '._associate_floatingip_to_port')
    @mock.patch(AWS_UTILS + '.allocate_elastic_ip')
    def test_create_floatingip_with_failure_in_creating(
            self, mock_allocate, mock_assoc, mock_create, mock_delete):
        floatingip = {'floatingip': {'port_id': 'fake_port_id'}}
        mock_allocate.return_value = {'PublicIp': '192.169.10.1'}
        mock_create.side_effect = exceptions.PhysicalNetworkNameError()
        mock_assoc.return_value = None
        mock_delete.return_value = {}
        self.assertRaises(exceptions.PhysicalNetworkNameError,
                          self._driver.create_floatingip, self.context,
                          floatingip)
        self.assertTrue(mock_assoc.called)
        self.assertTrue(mock_delete.called)

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
    @mock.patch(AWS_UTILS + '.delete_elastic_ip')
    @mock.patch(L3_NAT_DBONLY_MIXIN + '.get_floatingip')
    def test_delete_floatingip_success(self, mock_get, mock_delete_elastic_ip,
                                       mock_delete_floating_ip):
        fake_id = 'fake_id'
        mock_get.return_value = {'floating_ip_address': '192.169.10.1'}
        mock_delete_elastic_ip.return_value = {}
        mock_delete_floating_ip.return_value = None
        self.assertIsNone(self._driver.delete_floatingip(self.context,
                                                         fake_id))
        self.assertTrue(mock_get.called)
        mock_get.assert_called_once_with(self.context, fake_id)
        self.assertTrue(mock_delete_elastic_ip.called)
        mock_delete_floating_ip.assert_called_once_with(self.context, fake_id)

    @mock_ec2
    @mock.patch(L3_NAT_WITH_DVR_DB_MIXIN + '.delete_floatingip')
    @mock.patch(L3_NAT_DBONLY_MIXIN + '.get_floatingip')
    def test_delete_floatingip_failure(self, mock_get, mock_delete):
        fake_id = 'fake_id'
        mock_get.return_value = {'floating_ip_address': '192.169.10.1'}
        mock_delete.return_value = {}
        self.assertRaises(AwsException, self._driver.delete_floatingip,
                          self.context, fake_id)
        self.assertTrue(mock_get.called)
        mock_get.assert_called_once_with(self.context, fake_id)

    @mock_ec2
    @mock.patch(L3_NAT_WITH_DVR_DB_MIXIN + '.update_floatingip')
    @mock.patch(AWS_UTILS + '.disassociate_elastic_ip_from_ec2_instance')
    @mock.patch(L3_NAT_DBONLY_MIXIN + '.get_floatingip')
    def test_update_floatingip_with_port(self, mock_get, mock_disassociate,
                                         mock_update):
        fake_id = 'fake_id'
        floatingip = {'floatingip': {'port_id': None}}
        mock_get.return_value = {'floating_ip_address': '192.169.10.1'}
        mock_disassociate.return_value = {}
        mock_update.return_value = None
        self.assertIsNone(self._driver.update_floatingip(self.context, fake_id,
                                                         floatingip))
        self.assertTrue(mock_get.called)
        self.assertTrue(mock_disassociate.called)
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
    @mock.patch(AWS_UTILS + '.disassociate_elastic_ip_from_ec2_instance')
    @mock.patch(L3_NAT_DBONLY_MIXIN + '.get_floatingip')
    def test_update_floatingip_failure_with_port(
            self, mock_get, mock_disassociate, mock_update):
        fake_id = 'fake_id'
        floatingip = {'floatingip': {'port': 'fake_port_id'}}
        mock_get.return_value = {'floating_ip_address': '192.169.10.1'}
        mock_disassociate.return_value = {}
        mock_update.side_effect = exceptions.PhysicalNetworkNameError()
        self.assertRaises(exceptions.PhysicalNetworkNameError,
                          self._driver.update_floatingip, self.context,
                          fake_id, floatingip)
        self.assertTrue(mock_get.called)
        mock_get.assert_called_once_with(self.context, fake_id)

    @mock_ec2
    @mock.patch(L3_NAT_DBONLY_MIXIN + '.create_router')
    @mock.patch(AWS_UTILS + '.create_internet_gateway_resource')
    def test_create_router_success(self, mock_create_ig, mock_create_router):
        mock_create_ig.return_value = FakeInternetGateway()
        mock_create_router.return_value = {'id': 'fake_id'}
        router = {'router': {'name': 'fake_name'}}
        response = self._driver.create_router(self.context, router)
        self.assertIsInstance(response, dict)
        mock_create_router.assert_called_once_with(self.context, router)

    @mock_ec2
    @mock.patch(L3_NAT_DBONLY_MIXIN + '.create_router')
    @mock.patch(AWS_UTILS + '.create_internet_gateway_resource')
    def test_create_router_failure(self, mock_create_ig, mock_create):
        mock_create_ig.return_value = FakeInternetGateway()
        mock_create.side_effect = exceptions.PhysicalNetworkNameError
        router = {'router': {'name': 'fake_name'}}
        self.assertRaises(exceptions.PhysicalNetworkNameError,
                          self._driver.create_router, self.context, router)

    @mock_ec2
    @mock.patch(L3_NAT_DBONLY_MIXIN + '.delete_router')
    @mock.patch(AWS_UTILS + '.detach_internet_gateway_by_router_id')
    def test_delete_router_success(self, mock_detach, mock_delete):
        mock_delete.return_value = None
        mock_detach.return_value = None
        fake_id = 'fake_id'
        self.assertIsNone(self._driver.delete_router(self.context, fake_id))
        self.assertTrue(mock_delete.called)
        mock_delete.assert_called_once_with(self.context, fake_id)

    @mock_ec2
    @mock.patch(L3_NAT_DBONLY_MIXIN + '.delete_router')
    @mock.patch(AWS_UTILS + '.detach_internet_gateway_by_router_id')
    def test_delete_router_failure(self, mock_detach, mock_delete):
        mock_delete.side_effect = exceptions.PhysicalNetworkNameError
        mock_detach.return_value = None
        fake_id = 'fake_id'
        self.assertRaises(exceptions.PhysicalNetworkNameError,
                          self._driver.delete_router, self.context, fake_id)

    @mock_ec2
    @mock.patch(L3_NAT_DBONLY_MIXIN + '.update_router')
    @mock.patch(AWS_UTILS + '.create_tags_internet_gw_from_router_id')
    def test_update_router_success(self, mock_create_tags, mock_update):
        mock_update.return_value = {'id': "fake_id"}
        mock_create_tags.return_value = None
        router = {'router': {'name': 'fake_name'}}
        fake_id = 'fake_id'
        response = self._driver.update_router(self.context, fake_id, router)
        self.assertIsInstance(response, dict)
        mock_update.assert_called_once_with(self.context, fake_id, router)
        self.assertTrue(mock_create_tags.called)

    @mock_ec2
    @mock.patch(L3_NAT_DBONLY_MIXIN + '.add_router_interface')
    @mock.patch(AWS_UTILS + '.create_default_route_to_ig')
    @mock.patch(AWS_UTILS + '.get_route_table_by_router_id')
    @mock.patch(AWS_UTILS + '.attach_internet_gateway')
    @mock.patch(AWS_UTILS + '.get_vpc_from_neutron_network_id')
    @mock.patch(AWS_UTILS + '.get_internet_gw_from_router_id')
    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_subnet')
    def test_add_router_interface(self, mock_subnet, mock_get_ig, mock_get_vpc,
                                  mock_attach, mock_get_route_table,
                                  mock_create_route, mock_add_router):
        interface_info = {'subnet_id': 'fake_subnet_id'}
        mock_subnet.return_value = {'network_id': 'fake_network_id'}
        mock_get_ig.return_value = "fake_gateway_id"
        mock_get_vpc.return_value = "fake_vpc_id"
        mock_attach.return_value = {}
        mock_get_route_table.return_value = [{'RouteTableId': 'fake_id'}]
        mock_create_route.return_value = {}
        mock_add_router.return_value = {'id': 'fake_id',
                                        'subnet_id': 'fake_subnet_id'}
        response = self._driver.add_router_interface(
            self.context, self.context.current['id'], interface_info)
        self.assertIsInstance(response, dict)
        mock_add_router.assert_called_once_with(
            self.context, self.context.current['id'], interface_info)

    @mock_ec2
    @mock.patch(L3_NAT_DBONLY_MIXIN + '.remove_router_interface')
    @mock.patch(AWS_UTILS + '.delete_default_route_to_ig')
    @mock.patch(AWS_UTILS + '.get_route_table_by_router_id')
    @mock.patch(AWS_UTILS + '.detach_internet_gateway_by_router_id')
    def test_remove_router_interface(self, mock_detach, mock_get_route_table,
                                     mock_delete, mock_remove_interface):
        interface_info = {'port_id': 'fake_port_id'}
        mock_detach.return_value = {}
        mock_get_route_table.return_value = [{'RouteTableId': 'fake_id'}]
        mock_delete.return_value = {}
        mock_remove_interface.return_value = {'id': 'fake_id',
                                              'subnet_id': 'fake_subnet_id'}
        response = self._driver.remove_router_interface(
            self.context, self.context.current['id'], interface_info)
        self.assertIsInstance(response, dict)
        mock_remove_interface.assert_called_once_with(
            self.context, self.context.current['id'], interface_info)
