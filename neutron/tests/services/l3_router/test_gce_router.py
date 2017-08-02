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
import os

from neutron.common import exceptions
from neutron_lib import constants as const

from neutron.services.l3_router.gce_router_plugin import GceRouterPlugin

from neutron.tests import base
from neutron.tests.common.gce import gce_mock
from neutron.tests.unit.extensions import test_securitygroup as test_sg

DATA_DIR = os.path.dirname(os.path.abspath("gce_mock.py")) + '/data'
L3_NAT_WITH_DVR_DB_MIXIN = 'neutron.db.l3_dvr_db.L3_NAT_with_dvr_db_mixin'
GCEROUTERPLUG = 'neutron.services.l3_router.gce_router_plugin.GceRouterPlugin'
GCEUTILS = 'neutron.common.gceutils'
EXTRAROUTE_DBONLY_MIXIN = 'neutron.db.extraroute_db.ExtraRoute_dbonly_mixin'


class TestGceRouterPlugin(test_sg.SecurityGroupsTestCase, base.BaseTestCase):
    def setUp(self):
        super(TestGceRouterPlugin, self).setUp()
        self.service_patcher = mock.patch(
            'neutron.common.gceutils.get_gce_service').start()
        mock_service = self.service_patcher.start()
        mock_service.side_effect = gce_mock.get_gce_service
        self.addCleanup(self.service_patcher.stop)
        self._driver = GceRouterPlugin()
        self._driver.gce_zone = 'us-central1-c'
        self._driver.gce_region = 'us-central1'
        self._driver.gce_project = 'omni-163105'
        self._driver.gce_svc_key = "{0}/omni.json".format(DATA_DIR)
        self.context = self._create_fake_context()

    def _create_fake_context(self):
        context = mock.Mock()
        context.current = {}
        context.current['id'] = "fake_id_1234"
        context.current['cidr'] = "192.168.1.0/24"
        context.current['network_id'] = "fake_network_id_1234"
        return context

    @mock.patch(L3_NAT_WITH_DVR_DB_MIXIN + '.delete_floatingip')
    @mock.patch(GCEROUTERPLUG + '._cleanup_floatingip')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.get_floatingip')
    def test_delete_floatingip(self, mock_l3_get, mock_cleanup, mock_l3_del):

        floatingip = {'floating_ip_address': '192.169.10.1'}
        mock_l3_get.return_value = floatingip
        mock_cleanup.side_effect = gce_mock.return_nothing
        mock_l3_del.side_effect = gce_mock.return_nothing

        self.assertIsNone(self._driver.delete_floatingip(
            self.context, self.context.current.get('id')))
        mock_cleanup.assert_called_once_with(
            self._driver.gce_svc, self._driver.gce_project,
            self._driver.gce_region, floatingip.get('floating_ip_address'))
        mock_l3_del.assert_called_once_with(
            self.context, self.context.current.get('id'))

    @mock.patch(L3_NAT_WITH_DVR_DB_MIXIN + '.update_floatingip')
    @mock.patch(GCEROUTERPLUG + '._associate_floatingip_to_port')
    @mock.patch(GCEUTILS + '.release_floatingip')
    @mock.patch('neutron.db.l3_db.L3_NAT_dbonly_mixin.get_floatingip')
    def test_update_floatingip(self, mock_l3_get, mock_release, mock_assoc,
                               mock_l3_update):

        mock_release.side_effect = gce_mock.return_nothing
        mock_assoc.side_effect = gce_mock.return_nothing
        mock_l3_update.side_effect = gce_mock.return_nothing

        # Case 1: when port_id is present/True
        floatingip = {'floatingip': {'port_id': False}}
        orig_floatingip = {'floating_ip_address': '192.168.1.0'}
        mock_l3_get.return_value = orig_floatingip

        self.assertIsNone(self._driver.update_floatingip(
            self.context, self.context.current.get('id'),
            floatingip))
        mock_release.assert_called_with(
            self._driver.gce_svc, self._driver.gce_project,
            self._driver.gce_region,
            orig_floatingip.get('floating_ip_address'))
        mock_l3_update.assert_called_with(
            self.context, self.context.current.get('id'), floatingip)
        self.assertFalse(mock_assoc.called)

        # Case 2: When port_id is not present/False
        floatingip = {'floatingip': {'port_id': True}}

        self.assertIsNone(self._driver.update_floatingip(
            self.context, self.context.current.get('id'),
            floatingip))
        mock_release.assert_called_with(
            self._driver.gce_svc, self._driver.gce_project,
            self._driver.gce_region,
            orig_floatingip.get('floating_ip_address'))
        mock_assoc.assert_called_once_with(
            self.context, orig_floatingip.get('floating_ip_address'),
            floatingip.get('floatingip').get('port_id'))
        mock_l3_update.assert_called_with(
            self.context, self.context.current.get('id'),
            floatingip)

    @mock.patch(GCEUTILS + '.assign_floatingip')
    @mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2.get_port')
    def test_associate_floatingip_to_port(self, mock_neutron_getport,
                                          mock_assignip):

        mock_assignip.side_effect = gce_mock.return_nothing
        floating_ip_address = '192.168.20.2'

        # Case 1: if len(port['fixed_ips'] > 0, But ip_address is not present)
        port = {'fixed_ips': [{'ip_address': None}]}
        mock_neutron_getport.return_value = port
        self.assertRaises(exceptions.FloatingIpSetupException,
                          self._driver._associate_floatingip_to_port,
                          self.context, floating_ip_address,
                          self.context.current.get('id'))
        self.assertFalse(mock_assignip.called)

        # Case 2: if len(port['fixed_ips']) == 0
        port = {'fixed_ips': []}
        mock_neutron_getport.return_value = port
        self.assertRaises(exceptions.FloatingIpSetupException,
                          self._driver._associate_floatingip_to_port,
                          self.context, floating_ip_address,
                          self.context.current.get('id'))
        self.assertFalse(mock_assignip.called)

        # Case 3: if len(port['fixed_ips']) > 0 and ip_address is present
        port = {'fixed_ips': [{'ip_address': '192.168.10.1'}]}
        mock_neutron_getport.return_value = port
        self.assertIsNone(self._driver._associate_floatingip_to_port(
            self.context, floating_ip_address,
            self.context.current.get('id')))
        mock_assignip.assert_called_once_with(
            self._driver.gce_svc, self._driver.gce_project,
            self._driver.gce_zone, port.get('fixed_ips')[0].get('ip_address'),
            floating_ip_address)

    @mock.patch(GCEROUTERPLUG + '._cleanup_floatingip')
    @mock.patch(L3_NAT_WITH_DVR_DB_MIXIN + '.create_floatingip')
    @mock.patch(GCEROUTERPLUG + '._associate_floatingip_to_port')
    @mock.patch(GCEUTILS + '.allocate_floatingip')
    def test_create_floatingip(self, mock_allocateip, mock_associp,
                               mock_l3_createip, mock_cleanupip):

        floatingip = {'floatingip': {'port_id': False}}
        public_ip_allocated = '192.168.20.2'
        res = '192.168.10.1'
        mock_allocateip.return_value = public_ip_allocated
        mock_l3_createip.return_value = res
        mock_associp.side_effect = gce_mock.return_nothing
        mock_cleanupip.side_effect = gce_mock.return_nothing

        # Case 1: port_id = False, _associate_floatingip_to_port is not called
        self.assertEqual((self._driver.create_floatingip(
            self.context, floatingip)), res)
        self.assertFalse(mock_associp.called)
        mock_l3_createip.assert_called_with(
            self.context, floatingip,
            initial_status=const.FLOATINGIP_STATUS_DOWN)

        # Case 2: port_id = True, _associate_floatingip_to_port is called
        floatingip = {'floatingip': {'port_id': True}}
        self.assertEqual((self._driver.create_floatingip(
            self.context, floatingip)), res)
        mock_associp.assert_called_once_with(
            self.context, public_ip_allocated,
            floatingip.get('floatingip').get('port_id'))
        mock_l3_createip.assert_called_with(
            self.context, floatingip,
            initial_status=const.FLOATINGIP_STATUS_DOWN)

        # Case 3: create_floatingip returns an exception, cleanup_floatingip is
        # called
        mock_l3_createip.side_effect = exceptions.PhysicalNetworkNameError()
        self.assertRaises(exceptions.PhysicalNetworkNameError,
                          self._driver.create_floatingip,
                          self.context, floatingip)
        mock_cleanupip.assert_called_with(
            self._driver.gce_svc, self._driver.gce_project,
            self._driver.gce_region, public_ip_allocated)

        # Case 4: allocate_floatingip returns an excpetion
        mock_allocateip.side_effect = exceptions.PhysicalNetworkNameError()
        self.assertRaises(exceptions.PhysicalNetworkNameError,
                          self._driver.create_floatingip,
                          self.context, floatingip)

    @mock.patch(GCEUTILS + '.release_floatingip')
    @mock.patch(GCEUTILS + '.delete_floatingip')
    def test_cleanup_floatingip(self, mock_delete, mock_release):

        floatingip = 'anyip'

        mock_delete.side_effect = gce_mock.return_nothing
        mock_release.side_effect = gce_mock.return_nothing

        self.assertIsNone(self._driver._cleanup_floatingip(
            self._driver.gce_svc, self._driver.gce_project,
            self._driver.gce_region, floatingip))

        mock_release.assert_called_once_with(
            self._driver.gce_svc, self._driver.gce_project,
            self._driver.gce_region, floatingip)

        mock_delete.assert_called_once_with(
            self._driver.gce_svc, self._driver.gce_project,
            self._driver.gce_region, floatingip)

    @mock.patch('neutron.db.l3_db.L3_NAT_db_mixin.create_router')
    def test_create_router(self, mock_create_router):

        router = {'router': {'name': 'TestRouter'}}
        mock_create_router.side_effect = gce_mock.return_nothing
        self.assertIsNone(self._driver.create_router(self.context, router))
        mock_create_router.assert_called_once_with(self.context, router)

    @mock.patch('neutron.db.l3_db.L3_NAT_db_mixin.delete_router')
    def test_delete_router(self, mock_delete_router):

        mock_delete_router.side_effect = gce_mock.return_nothing
        self.assertIsNone(self._driver.delete_router(
            self.context, self.context.current.get('id')))
        mock_delete_router.assert_called_once_with(
            self.context, self.context.current.get('id'))

    @mock.patch(EXTRAROUTE_DBONLY_MIXIN + '.update_router')
    def test_update_router(self, mock_update_router):

        router = 'some_router'
        mock_update_router.side_effect = gce_mock.return_nothing
        self.assertIsNone(self._driver.update_router(
            self.context, self.context.current.get('id'), router))
        mock_update_router.assert_called_once_with(
            self.context, self.context.current.get('id'), router)

    @mock.patch(L3_NAT_WITH_DVR_DB_MIXIN + '.add_router_interface')
    def test_add_router_interface(self, mock_add_interface):

        router_id = 'some_id'
        interface_info = 'some_info'

        mock_add_interface.side_effect = gce_mock.return_nothing
        self.assertIsNone(self._driver.add_router_interface(self.context,
                          router_id, interface_info))
        mock_add_interface.assert_called_once_with(
            self.context, router_id, interface_info)

    @mock.patch(L3_NAT_WITH_DVR_DB_MIXIN + '.remove_router_interface')
    def test_remove_router_interface(self, mock_remove_interface):

        router_id = 'some_id'
        interface_info = 'some_info'

        mock_remove_interface.side_effect = gce_mock.return_nothing
        self.assertIsNone(self._driver.remove_router_interface(self.context,
                          router_id, interface_info))
        mock_remove_interface.assert_called_once_with(
            self.context, router_id, interface_info)
