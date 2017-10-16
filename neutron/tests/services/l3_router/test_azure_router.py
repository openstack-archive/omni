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

from devtools_testutils.mgmt_testcase import fake_settings
from msrestazure.azure_exceptions import CloudError
from neutron.services.l3_router.azure_router_plugin import AzureRouterPlugin
from neutron.tests import base
from neutron.tests.common.azure import azure_mock
from neutron_lib import constants as const
from neutron_lib import exceptions
from neutron_lib.exceptions import l3 as l3_exceptions

RESOURCE_GROUP = 'omni_test_group'
CLIENT_SECRET = 'fake_key'
L3_NAT_DVR_DB = 'neutron.db.l3_dvr_db.L3_NAT_with_dvr_db_mixin'
EXTRAROUTE_DB = 'neutron.db.extraroute_db.ExtraRoute_dbonly_mixin'


class TestAzureRouterPlugin(base.BaseTestCase):
    def setUp(self):
        super(TestAzureRouterPlugin, self).setUp()
        self.driver = AzureRouterPlugin()
        self.creds_patcher = mock.patch(
            'neutron.common.azure.utils.get_credentials')
        mock_creds = self.creds_patcher.start()
        mock_creds.side_effect = azure_mock.get_fake_credentials
        self.addCleanup(self.creds_patcher.stop)
        self.driver.tenant_id = fake_settings.TENANT_ID
        self.driver.client_id = fake_settings.CLIENT_OID
        self.driver.client_secret = CLIENT_SECRET
        self.driver.subscription_id = fake_settings.SUBSCRIPTION_ID
        self.driver.region = "eastus"
        self.driver.resource_group = RESOURCE_GROUP
        self.context = self._create_fake_context()

    def _create_fake_context(self):
        context = mock.Mock()
        context.current = {}
        context.current['id'] = "fake_id"
        context.current['cidr'] = "192.168.1.0/24"
        context.current['network_id'] = "fake_network_id"
        return context

    @mock.patch(L3_NAT_DVR_DB + ".create_floatingip")
    @mock.patch("neutron.common.azure.utils.allocate_floatingip")
    @mock.patch(
        "neutron.common.azure.utils.check_resource_existence")
    def test_create_floatingip_without_port(
            self, mock_check_rg, mock_allocate, mock_create):
        mock_check_rg.side_effect = azure_mock.get_fake_resource_group
        mock_allocate.side_effect = azure_mock.get_fake_public_ip
        mock_create.return_value = None
        floatingip = {'floatingip': {'port_id': None}}
        self.assertIsNone(self.driver.create_floatingip(
            self.context, floatingip))
        mock_allocate.assert_called_once_with(
            self.driver.network_client, self.driver.resource_group,
            self.driver.region)
        mock_create.assert_called_once_with(
            self.context, floatingip,
            initial_status=const.FLOATINGIP_STATUS_DOWN)

    @mock.patch(L3_NAT_DVR_DB + ".create_floatingip")
    @mock.patch("neutron.common.azure.utils.update_nic")
    @mock.patch("neutron.common.azure.utils.get_nic")
    @mock.patch("neutron.common.azure.utils.allocate_floatingip")
    @mock.patch(
        "neutron.common.azure.utils.check_resource_existence")
    def test_create_floatingip_with_port(
            self, mock_check_rg, mock_allocate, mock_get, mock_update,
            mock_create):
        mock_check_rg.side_effect = azure_mock.get_fake_resource_group
        mock_allocate.side_effect = azure_mock.get_fake_public_ip
        mock_get.side_effect = azure_mock.get_fake_nic
        mock_update.side_effect = azure_mock.create_anything
        mock_create.return_value = None
        floatingip = {'floatingip': {'port_id': "fake_port_id"}}
        self.assertIsNone(self.driver.create_floatingip(
            self.context, floatingip))
        mock_allocate.assert_called_once_with(
            self.driver.network_client, self.driver.resource_group,
            self.driver.region)
        self.assertTrue(mock_get.called)
        mock_create.assert_called_once_with(
            self.context, floatingip,
            initial_status=const.FLOATINGIP_STATUS_ACTIVE)

    @mock.patch("neutron.common.azure.utils.get_nic")
    @mock.patch("neutron.common.azure.utils.allocate_floatingip")
    @mock.patch(
        "neutron.common.azure.utils.check_resource_existence")
    def test_create_floatingip_with_error(
            self, mock_check_rg, mock_allocate, mock_get):
        mock_check_rg.side_effect = azure_mock.get_fake_resource_group
        mock_allocate.side_effect = azure_mock.get_fake_public_ip
        mock_get.side_effect = exceptions.NotFound
        floatingip = {'floatingip': {'port_id': "fake_port_id"}}
        self.assertRaises(
            exceptions.NotFound, self.driver.create_floatingip,
            self.context, floatingip)

    @mock.patch(L3_NAT_DVR_DB + ".update_floatingip")
    @mock.patch("neutron.common.azure.utils.update_nic")
    @mock.patch("neutron.common.azure.utils.get_nic")
    @mock.patch(L3_NAT_DVR_DB + ".get_floatingip")
    @mock.patch(
        "neutron.common.azure.utils.check_resource_existence")
    def test_update_floatingip_without_port(
            self, mock_check_rg, mock_get_fip, mock_get_nic, mock_update_nic,
            mock_update_fip):
        mock_check_rg.side_effect = azure_mock.get_fake_resource_group
        mock_get_fip.return_value = {"floating_ip_address": "52.52.134.32",
                                     "port_id": "fake_port_id"}
        mock_get_nic.side_effect = azure_mock.get_fake_nic
        mock_update_nic.side_effect = azure_mock.create_anything
        mock_update_fip.return_value = None
        floatingip = {'floatingip': {'port_id': None}}
        self.assertIsNone(self.driver.update_floatingip(
            self.context, "fake_id", floatingip))
        mock_get_fip.assert_called_once_with(self.context, "fake_id")
        self.assertTrue(mock_get_nic.called)
        mock_update_fip.assert_called_once_with(
            self.context, "fake_id", floatingip)

    @mock.patch(L3_NAT_DVR_DB + ".update_floatingip")
    @mock.patch("neutron.common.azure.utils.update_nic")
    @mock.patch("neutron.common.azure.utils.get_nic")
    @mock.patch("neutron.common.azure.utils.get_floatingip")
    @mock.patch(L3_NAT_DVR_DB + ".get_floatingip")
    @mock.patch(
        "neutron.common.azure.utils.check_resource_existence")
    def test_update_floatingip_with_port(
            self, mock_check_rg, mock_l3_dvr_get_fip, mock_utils_get_fip,
            mock_get_nic, mock_update_nic, mock_update_fip):
        mock_check_rg.side_effect = azure_mock.get_fake_resource_group
        mock_l3_dvr_get_fip.return_value = {
            "floating_ip_address": "52.52.134.32",
            "port_id": "fake_port_id"
        }
        mock_utils_get_fip.side_effect = azure_mock.get_fake_public_ip
        mock_get_nic.side_effect = azure_mock.get_fake_nic
        mock_update_nic.side_effect = azure_mock.create_anything
        mock_update_fip.return_value = None
        floatingip = {'floatingip': {'port_id': "fake_port_id"}}
        self.assertIsNone(self.driver.update_floatingip(
            self.context, "fake_id", floatingip))
        mock_l3_dvr_get_fip.assert_called_once_with(self.context, "fake_id")
        mock_utils_get_fip.assert_called_once_with(
            self.driver.network_client, self.driver.resource_group,
            "52.52.134.32")
        mock_update_fip.assert_called_once_with(
            self.context, "fake_id", floatingip)

    @mock.patch(L3_NAT_DVR_DB + ".get_floatingip")
    @mock.patch(
        "neutron.common.azure.utils.check_resource_existence")
    def test_update_floatingip_with_error(self, mock_check_rg, mock_get_fip):
        mock_check_rg.side_effect = azure_mock.get_fake_resource_group
        mock_get_fip.side_effect = exceptions.NotFound
        floatingip = {'floatingip': {'port_id': "fake_port_id"}}
        self.assertRaises(
            exceptions.NotFound, self.driver.update_floatingip,
            self.context, "fake_id", floatingip)

    @mock.patch(L3_NAT_DVR_DB + ".delete_floatingip")
    @mock.patch("neutron.common.azure.utils.delete_floatingip")
    @mock.patch("neutron.common.azure.utils.get_floatingip")
    @mock.patch(L3_NAT_DVR_DB + ".get_floatingip")
    @mock.patch(
        "neutron.common.azure.utils.check_resource_existence")
    def test_delete_floatingip(
            self, mock_check_rg, mock_l3_dvr_get_fip, mock_utils_get_fip,
            mock_utils_delete_fip, mock_l3_dvr_delete_fip):
        mock_check_rg.side_effect = azure_mock.get_fake_resource_group
        mock_l3_dvr_get_fip.return_value = {
            "floating_ip_address": "52.52.134.32",
            "port_id": None
        }
        mock_utils_get_fip.side_effect = azure_mock.get_fake_public_ip
        mock_utils_delete_fip.side_effect = azure_mock.delete_anything
        mock_l3_dvr_delete_fip.return_value = None
        self.assertIsNone(self.driver.delete_floatingip(
            self.context, "fake_id"))
        mock_l3_dvr_get_fip.assert_called_once_with(self.context, "fake_id")
        mock_utils_get_fip.assert_called_once_with(
            self.driver.network_client, self.driver.resource_group,
            "52.52.134.32")
        mock_utils_delete_fip.assert_called_once_with(
            self.driver.network_client, self.driver.resource_group,
            "fake_public_ip")

    @mock.patch("neutron.common.azure.utils.delete_floatingip")
    @mock.patch("neutron.common.azure.utils.get_floatingip")
    @mock.patch(L3_NAT_DVR_DB + ".get_floatingip")
    @mock.patch(
        "neutron.common.azure.utils.check_resource_existence")
    def test_delete_floatingip_with_error(
            self, mock_check_rg, mock_l3_dvr_get_fip, mock_utils_get_fip,
            mock_utils_delete_fip):
        mock_check_rg.side_effect = azure_mock.get_fake_resource_group
        mock_l3_dvr_get_fip.return_value = {
            "floating_ip_address": "52.52.134.32",
            "port_id": None
        }
        mock_utils_get_fip.side_effect = azure_mock.get_fake_public_ip
        mock_utils_delete_fip.side_effect = CloudError(
            "fake_response", error="Error while deleting floatingip")
        self.assertRaises(CloudError, self.driver.delete_floatingip,
                          self.context, "fake_id")
        mock_l3_dvr_get_fip.assert_called_once_with(self.context, "fake_id")
        mock_utils_get_fip.assert_called_once_with(
            self.driver.network_client, self.driver.resource_group,
            "52.52.134.32")

    @mock.patch('neutron.db.l3_db.L3_NAT_db_mixin.create_router')
    def test_create_router(self, mock_create_router):
        router = {'router': {'name': 'TestRouter'}}
        mock_create_router.return_value = None
        self.assertIsNone(self.driver.create_router(self.context, router))
        mock_create_router.assert_called_once_with(self.context, router)

    @mock.patch('neutron.db.l3_db.L3_NAT_db_mixin.create_router')
    def test_create_router_with_error(self, mock_create_router):
        router = {'router': {'name': 'TestRouter'}}
        mock_create_router.side_effect = exceptions.Conflict
        self.assertRaises(exceptions.Conflict, self.driver.create_router,
                          self.context, router)

    @mock.patch('neutron.db.l3_db.L3_NAT_db_mixin.delete_router')
    def test_delete_router(self, mock_delete_router):
        mock_delete_router.return_value = None
        self.assertIsNone(self.driver.delete_router(
            self.context, self.context.current['id']))
        mock_delete_router.assert_called_once_with(
            self.context, self.context.current['id'])

    @mock.patch('neutron.db.l3_db.L3_NAT_db_mixin.delete_router')
    def test_delete_router_with_error(self, mock_delete_router):
        mock_delete_router.side_effect = l3_exceptions.RouterInUse
        self.assertRaises(l3_exceptions.RouterInUse, self.driver.delete_router,
                          self.context, self.context.current['id'])

    @mock.patch(EXTRAROUTE_DB + '.update_router')
    def test_update_router(self, mock_update_router):
        router = 'TestRouter'
        mock_update_router.return_value = None
        self.assertIsNone(self.driver.update_router(
            self.context, self.context.current['id'], router))
        mock_update_router.assert_called_once_with(
            self.context, self.context.current['id'], router)

    @mock.patch(EXTRAROUTE_DB + '.update_router')
    def test_update_router_with_error(self, mock_update_router):
        router = 'TestRouter'
        mock_update_router.side_effect = l3_exceptions.RouterNotFound(
            router_id=self.context.current['id'])
        self.assertRaises(
            l3_exceptions.RouterNotFound, self.driver.update_router,
            self.context, self.context.current['id'], router)

    @mock.patch(L3_NAT_DVR_DB + '.add_router_interface')
    def test_add_router_interface(self, mock_add_interface):
        router_id = 'fake_router_id'
        interface_info = 'fake_interface_info'
        mock_add_interface.return_value = None
        self.assertIsNone(self.driver.add_router_interface(
            self.context, router_id, interface_info))
        mock_add_interface.assert_called_once_with(
            self.context, router_id, interface_info)

    @mock.patch(L3_NAT_DVR_DB + '.add_router_interface')
    def test_add_router_interface_with_error(self, mock_add_interface):
        router_id = 'fake_router_id'
        interface_info = {"port_id": "fake_port_id"}
        mock_add_interface.side_effect = exceptions.Conflict
        self.assertRaises(
            exceptions.Conflict, self.driver.add_router_interface,
            self.context, router_id, interface_info)

    @mock.patch(L3_NAT_DVR_DB + '.remove_router_interface')
    def test_remove_router_interface(self, mock_remove_interface):
        router_id = 'fake_router_id'
        interface_info = {"port_id": "fake_port_id"}
        mock_remove_interface.side_effect = \
            l3_exceptions.RouterInterfaceNotFound(
                router_id=router_id, port_id=interface_info['port_id'])
        self.assertRaises(l3_exceptions.RouterInterfaceNotFound,
                          self.driver.remove_router_interface,
                          self.context, router_id, interface_info)
