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

from neutron.extensions import securitygroup as sg
from neutron.manager import NeutronManager
from neutron.plugins.ml2.drivers.gce.mech_gce import GceMechanismDriver
from neutron.plugins.ml2.drivers.gce.mech_gce import SecurityGroupInvalidDirection  # noqa
from neutron.tests import base
from neutron.tests.common.gce import gce_mock
from neutron.tests.common.gce.gce_mock import FakeNeutronManager
from neutron.tests.unit.extensions import test_securitygroup as test_sg
from neutron_lib import constants as const

DATA_DIR = os.path.dirname(os.path.abspath("gce_mock.py")) + '/data'
NETWORKS_LINK = "projects/omni-163105/global/networks"
NETWORK_LINK = NETWORKS_LINK + "/net-03c4f178-670e-4805-a511-9470ca4a0b06"

if hasattr(NeutronManager, "get_plugin"):
    neutron_get_plugin = 'neutron.manager.NeutronManager.get_plugin'
else:
    neutron_get_plugin = 'neutron_lib.plugins.directory.get_plugin'


class GCENeutronTestCase(test_sg.SecurityGroupsTestCase, base.BaseTestCase):
    @mock.patch('neutron.common.gceutils.get_gce_service')
    def setUp(self, mock_service):
        mock_service.side_effect = gce_mock.get_gce_service
        super(GCENeutronTestCase, self).setUp()
        self._driver = GceMechanismDriver()
        self._driver.gce_zone = 'us-central1-c'
        self._driver.gce_region = 'us-central1'
        self._driver.gce_project = 'omni-163105'
        self._driver.gce_svc_key = "{0}/omni.json".format(DATA_DIR)
        self.context = self._create_fake_context()
        self._driver.initialize()

    def _create_fake_context(self):
        context = mock.Mock()
        context.current = {}
        context.current['id'] = "fake_id_1234"
        context.current['cidr'] = "192.168.1.0/24"
        context.current['network_id'] = "fake_network_id_1234"
        return context

    def get_fake_sg_rule(self, ethertype=const.IPv4, direction="ingress",
                         protocol=const.PROTO_NAME_TCP):
        data = {
            'id': 'fake_rule_id',
            'security_group_id': '4cd70774-cc67-4a87-9b39-7d1db38eb087',
            'direction': direction,
            'protocol': protocol,
            'ethertype': ethertype,
            'tenant_id': 'fake_tenant_id',
            'port_range_min': '22',
            'port_range_max': '22',
            'remote_ip_prefix': None,
            'remote_group_id': None
        }
        return data

    @mock.patch('neutron.common.gceutils.wait_for_operation')
    @mock.patch('neutron.common.gceutils.create_network')
    def test_create_network_postcommit(self, mock_create, mock_wait):
        mock_create.side_effect = gce_mock.create_anything
        mock_wait.side_effect = gce_mock.wait_for_operation
        self.assertIsNone(self._driver.create_network_postcommit(self.context))
        mock_wait.assert_called_once_with(self._driver.gce_svc,
                                          self._driver.gce_project,
                                          gce_mock.fake_operation())

    @mock.patch('neutron.common.gceutils.wait_for_operation')
    @mock.patch('neutron.common.gceutils.delete_network')
    def test_delete_network_postcommit(self, mock_delete, mock_wait):
        mock_delete.side_effect = gce_mock.delete_anything
        mock_wait.side_effect = gce_mock.wait_for_operation
        self.assertIsNone(self._driver.delete_network_postcommit(self.context))
        mock_wait.assert_called_once_with(self._driver.gce_svc,
                                          self._driver.gce_project,
                                          gce_mock.fake_operation())

    @mock.patch('neutron.common.gceutils.wait_for_operation')
    @mock.patch('neutron.common.gceutils.create_subnet')
    @mock.patch('neutron.common.gceutils.get_network')
    def test_create_subnet_postcommit(self, mock_get, mock_create, mock_wait):
        mock_get.side_effect = gce_mock.get_network
        mock_create.side_effect = gce_mock.create_anything
        mock_wait.side_effect = gce_mock.wait_for_operation
        self.assertIsNone(self._driver.create_subnet_postcommit(self.context))
        mock_wait.assert_called_once_with(self._driver.gce_svc,
                                          self._driver.gce_project,
                                          gce_mock.fake_operation())

    @mock.patch('neutron.common.gceutils.wait_for_operation')
    @mock.patch('neutron.common.gceutils.delete_subnet')
    def test_delete_subnet_postcommit(self, mock_delete, mock_wait):
        mock_delete.side_effect = gce_mock.delete_anything
        mock_wait.side_effect = gce_mock.wait_for_operation
        self.assertIsNone(self._driver.delete_subnet_postcommit(self.context))
        mock_wait.assert_called_once_with(self._driver.gce_svc,
                                          self._driver.gce_project,
                                          gce_mock.fake_operation())

    def test_convert_sg_to_gce_failure_with_wrong_ethertype(self):
        sg_rule = self.get_fake_sg_rule(ethertype=const.IPv6)
        self.assertRaises(sg.SecurityGroupRuleInvalidEtherType,
                          self._driver._convert_secgrp_rule_to_gce,
                          rule=sg_rule, network_link=NETWORK_LINK)

    def test_convert_sg_to_gce_failure_with_wrong_direction(self):
        sg_rule = self.get_fake_sg_rule(direction="egress")
        self.assertRaises(SecurityGroupInvalidDirection,
                          self._driver._convert_secgrp_rule_to_gce,
                          rule=sg_rule, network_link=NETWORK_LINK)

    def test_convert_sg_to_gce_failure_with_wrong_protocol(self):
        sg_rule = self.get_fake_sg_rule(protocol="fake_protocol")
        self.assertRaises(sg.SecurityGroupRuleInvalidProtocol,
                          self._driver._convert_secgrp_rule_to_gce,
                          rule=sg_rule, network_link=NETWORK_LINK)

    def test_convert_sg_to_gce_success(self):
        sg_rule = self.get_fake_sg_rule()
        gce_rule = self._driver._convert_secgrp_rule_to_gce(
            sg_rule, NETWORK_LINK)
        self.assertTrue(isinstance(gce_rule, dict))

    @mock.patch('neutron.common.gceutils.wait_for_operation')
    @mock.patch('neutron.common.gceutils.create_firewall_rule')
    def test_create_sg_rule(self, mock_create, mock_wait):
        mock_create.side_effect = gce_mock.create_anything
        mock_wait.side_effect = gce_mock.wait_for_operation
        sg_rule = self.get_fake_sg_rule()
        self.assertIsNone(
            self._driver._create_secgrp_rule(self.context, sg_rule,
                                             NETWORK_LINK))
        mock_wait.assert_called_once_with(self._driver.gce_svc,
                                          self._driver.gce_project,
                                          gce_mock.fake_operation())

    @mock.patch(neutron_get_plugin)
    @mock.patch('neutron.common.gceutils.wait_for_operation')
    @mock.patch('neutron.common.gceutils.update_firewall_rule')
    @mock.patch('neutron.common.gceutils.get_firewall_rule')
    def test_update_sg_rule(self, mock_get, mock_update, mock_wait,
                            mock_plugin):
        mock_get.side_effect = gce_mock.get_firewall_rule
        mock_update.side_effect = gce_mock.create_anything
        mock_wait.side_effect = gce_mock.wait_for_operation
        mock_plugin.side_effect = FakeNeutronManager
        sg_rule = self.get_fake_sg_rule()
        self.assertIsNone(
            self._driver._update_secgrp_rule(self.context, sg_rule['id']))
        self.assertTrue(mock_update.called)

    @mock.patch('neutron.common.gceutils.wait_for_operation')
    @mock.patch('neutron.common.gceutils.delete_firewall_rule')
    def test_delete_sg_rule(self, mock_delete, mock_wait):
        mock_delete.side_effect = gce_mock.delete_anything
        mock_wait.side_effect = gce_mock.wait_for_operation
        sg_rule = self.get_fake_sg_rule()
        self.assertIsNone(
            self._driver._delete_secgrp_rule(self.context, sg_rule['id']))
        mock_delete.assert_called_once_with(self._driver.gce_svc,
                                            self._driver.gce_project,
                                            "secgrp-" + sg_rule['id'])
