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
import uuid

from devtools_testutils.mgmt_testcase import fake_settings
from neutron.common.azure import utils
from neutron.extensions import securitygroup as sg
from neutron.manager import NeutronManager
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers.azure.mech_azure import azure_conf
from neutron.plugins.ml2.drivers.azure.mech_azure import AzureMechanismDriver
from neutron.tests import base
from neutron.tests.common.azure import azure_mock
from neutron_lib import exceptions
from neutron_lib import constants as const

import mock

RESOURCE_GROUP = 'omni_test_group'
CLIENT_SECRET = 'fake_key'

if hasattr(NeutronManager, "get_plugin"):
    neutron_get_plugin = 'neutron.manager.NeutronManager.get_plugin'
else:
    neutron_get_plugin = 'neutron_lib.plugins.directory.get_plugin'


class AzureNeutronTestCase(base.BaseTestCase):
    def setUp(self):
        super(AzureNeutronTestCase, self).setUp()
        self.creds_patcher = mock.patch(
            'neutron.common.azure.utils.get_credentials').start()
        mock_creds = self.creds_patcher.start()
        mock_creds.side_effect = azure_mock.get_fake_credentials
        self.addCleanup(self.creds_patcher.stop)
        azure_conf.tenant_id = fake_settings.TENANT_ID
        azure_conf.client_id = fake_settings.CLIENT_OID
        azure_conf.client_secret = CLIENT_SECRET
        azure_conf.subscription_id = fake_settings.SUBSCRIPTION_ID
        azure_conf.region = "eastus"
        azure_conf.resource_group = RESOURCE_GROUP
        self.context = self._create_fake_context()
        self.driver = AzureMechanismDriver()
        self.driver.initialize()

    def _create_fake_context(self):
        context = mock.Mock()
        context.current = {}
        context.current['network_id'] = "fake_network_id"
        context.current['cidr'] = "192.168.1.0/24"
        context.current['api'] = {}
        context.current['id'] = "fake_id"
        context.current['device_owner'] = []
        return context

    def get_fake_sg_rule(self, ethertype=const.IPv4, direction="ingress",
                         protocol=const.PROTO_NAME_TCP):
        data = {
            'id': str(uuid.uuid4()),
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

    @mock.patch("neutron.common.azure.utils.delete_network")
    @mock.patch(
        "neutron.common.azure.utils.check_resource_existence")
    def test_delete_network_postcommit(self, mock_check_rg, mock_delete_nw):
        mock_check_rg.side_effect = azure_mock.get_fake_resource_group
        mock_delete_nw.side_effect = azure_mock.delete_anything
        self.assertIsNone(self.driver.delete_network_postcommit(self.context))
        mock_delete_nw.assert_called_once_with(
            self.driver.network_client, azure_conf.resource_group,
            "net-" + self.context.current[api.ID])

    @mock.patch("neutron.common.azure.utils.create_subnet")
    @mock.patch("neutron.common.azure.utils.update_network")
    @mock.patch("neutron.common.azure.utils.get_network")
    @mock.patch(
        "neutron.common.azure.utils.check_resource_existence")
    def test_create_subnet_precommit_with_network(
            self, mock_check_rg, mock_get_nw, mock_update_nw,
            mock_create_subnet):
        mock_check_rg.side_effect = azure_mock.get_fake_resource_group
        mock_get_nw.side_effect = azure_mock.get_fake_network
        mock_update_nw.side_effect = azure_mock.create_anything
        mock_create_subnet.side_effect = azure_mock.create_anything
        self.assertIsNone(self.driver.create_subnet_precommit(self.context))
        mock_create_subnet.assert_called_once_with(
            self.driver.network_client, azure_conf.resource_group,
            "net-" + self.context.current['network_id'],
            "subnet-" + self.context.current[api.ID],
            {'address_prefix': self.context.current['cidr']})
        self.assertTrue(mock_get_nw.called)
        self.assertTrue(mock_update_nw.called)

    @mock.patch("neutron.common.azure.utils.create_subnet")
    @mock.patch("neutron.common.azure.utils.create_network")
    @mock.patch("neutron.common.azure.utils.get_network")
    @mock.patch(
        "neutron.common.azure.utils.check_resource_existence")
    def test_create_subnet_precommit_without_network(
            self, mock_check_rg, mock_get_nw, mock_create_nw,
            mock_create_subnet):
        mock_check_rg.side_effect = azure_mock.get_fake_resource_group
        mock_get_nw.side_effect = exceptions.NetworkNotFound(
            net_id="fake_network_id")
        mock_create_nw.side_effect = azure_mock.create_anything
        mock_create_subnet.side_effect = azure_mock.create_anything
        self.assertIsNone(self.driver.create_subnet_precommit(self.context))
        mock_create_subnet.assert_called_once_with(
            self.driver.network_client, azure_conf.resource_group,
            "net-" + self.context.current['network_id'],
            "subnet-" + self.context.current[api.ID],
            {'address_prefix': self.context.current['cidr']})
        self.assertTrue(mock_create_nw.called)

    @mock.patch("neutron.common.azure.utils.delete_subnet")
    @mock.patch(
        "neutron.common.azure.utils.check_resource_existence")
    def test_delete_subnet_precommit(self, mock_check_rg, mock_delete_subnet):
        mock_check_rg.side_effect = azure_mock.get_fake_resource_group
        mock_delete_subnet.side_effect = azure_mock.delete_anything
        self.assertIsNone(self.driver.delete_subnet_precommit(self.context))
        mock_delete_subnet.assert_called_once_with(
            self.driver.network_client, azure_conf.resource_group,
            "net-" + self.context.current['network_id'],
            "subnet-" + self.context.current[api.ID])

    @mock.patch("neutron.common.azure.utils.create_nic")
    @mock.patch("neutron.common.azure.utils.get_subnet")
    @mock.patch(
        "neutron.common.azure.utils.check_resource_existence")
    def test_create_port_precommit_without_sg(
            self, mock_check_rg, mock_get_subnet, mock_create_nic):
        mock_check_rg.side_effect = azure_mock.get_fake_resource_group
        mock_get_subnet.side_effect = azure_mock.get_fake_subnet
        mock_create_nic.side_effect = azure_mock.create_anything
        details = [{'ip_address': '192.168.1.5',
                    'subnet_id': 'fake_subnet_id'}]
        self.context.current['security_groups'] = []
        self.context.current["fixed_ips"] = details
        body = {
            'location': azure_conf.region,
            'ip_configurations': [{
                'name': "ipc-" + self.context.current['id'],
                'private_ip_address': details[0]['ip_address'],
                'private_ip_allocation_method': 'Static',
                'subnet': {'id': details[0]['subnet_id']},
            }]
        }
        self.assertIsNone(self.driver.create_port_precommit(self.context))
        self.assertTrue(mock_get_subnet.called)
        mock_create_nic.assert_called_once_with(
            self.driver.network_client, azure_conf.resource_group,
            "nic-" + self.context.current['id'], body)

    @mock.patch("neutron.common.azure.utils.create_nic")
    @mock.patch("neutron.common.azure.utils.get_sg")
    @mock.patch("neutron.common.azure.utils.get_subnet")
    @mock.patch(
        "neutron.common.azure.utils.check_resource_existence")
    def test_create_port_precommit_with_sg(
            self, mock_check_rg, mock_get_subnet, mock_get_sg,
            mock_create_nic):
        mock_check_rg.side_effect = azure_mock.get_fake_resource_group
        mock_get_subnet.side_effect = azure_mock.get_fake_subnet
        mock_get_sg.side_effect = azure_mock.get_fake_sg
        mock_create_nic.side_effect = azure_mock.create_anything
        details = [{'ip_address': '192.168.1.5',
                    'subnet_id': 'fake_subnet_id'}]
        self.context.current['security_groups'] = ["fake_openstack_id"]
        self.context.current["fixed_ips"] = details
        body = {
            'location': azure_conf.region,
            'ip_configurations': [{
                'name': "ipc-" + self.context.current['id'],
                'private_ip_address': details[0]['ip_address'],
                'private_ip_allocation_method': 'Static',
                'subnet': {'id': details[0]['subnet_id']},
            }],
            'network_security_group': {'id': "fake_sg_id"}
        }
        self.assertIsNone(self.driver.create_port_precommit(self.context))
        self.assertTrue(mock_get_subnet.called)
        self.assertTrue(mock_get_sg.called)
        mock_create_nic.assert_called_once_with(
            self.driver.network_client, azure_conf.resource_group,
            "nic-" + self.context.current['id'], body)

    @mock.patch("neutron.common.azure.utils.delete_nic")
    @mock.patch("neutron.common.azure.utils.get_nic")
    @mock.patch(
        "neutron.common.azure.utils.check_resource_existence")
    def test_delete_port_precommit(
            self, mock_check_rg, mock_get_nic, mock_delete_nic):
        mock_check_rg.side_effect = azure_mock.get_fake_resource_group
        mock_get_nic.side_effect = azure_mock.get_fake_nic
        mock_delete_nic.side_effect = azure_mock.delete_anything
        self.assertIsNone(self.driver.delete_port_precommit(self.context))
        self.assertTrue(mock_get_nic.called)
        mock_delete_nic.assert_called_once_with(
            self.driver.network_client, azure_conf.resource_group,
            "nic-" + self.context.current['id'])

    @mock.patch("neutron.common.azure.utils.create_sg_rule")
    @mock.patch("neutron.common.azure.utils.get_sg")
    @mock.patch(
        "neutron.common.azure.utils.check_resource_existence")
    def test_create_sg_rule(
            self, mock_check_rg, mock_get_sg, mock_create_sgrule):
        mock_check_rg.side_effect = azure_mock.get_fake_resource_group
        mock_get_sg.side_effect = azure_mock.get_fake_sg
        mock_create_sgrule.side_effect = azure_mock.create_anything
        sg_rule = self.get_fake_sg_rule()
        azure_rule = utils.convert_sg_rule(sg_rule)
        azure_rule['priority'] = 100
        self.assertIsNone(self.driver._create_secrule(
            security_group_rule=sg_rule))
        mock_create_sgrule.assert_called_once_with(
            self.driver.network_client, azure_conf.resource_group,
            "secgrp-" + sg_rule['security_group_id'],
            "secrule-" + sg_rule['id'], azure_rule)

    @mock.patch("neutron.common.azure.utils.delete_sg_rule")
    @mock.patch(
        "neutron.common.azure.utils.check_resource_existence")
    @mock.patch(neutron_get_plugin)
    def test_delete_sg_rule(
            self, mock_plugin, mock_check_rg, mock_delete_sgrule):
        mock_plugin.side_effect = azure_mock.FakeNeutronManager
        mock_check_rg.side_effect = azure_mock.get_fake_resource_group
        mock_delete_sgrule.side_effect = azure_mock.delete_anything
        self.assertIsNone(self.driver._delete_secrule(
            security_group_rule_id="fake_sg_rule_id", context=self.context))
        mock_delete_sgrule.assert_called_once_with(
            self.driver.network_client, azure_conf.resource_group,
            "secgrp-4cd70774-cc67-4a87-9b39-7d1db38eb087",
            "secrule-fake_sg_rule_id")

    @mock.patch("neutron.common.azure.utils.create_sg")
    @mock.patch(
        "neutron.common.azure.utils.check_resource_existence")
    def test_create_sg(self, mock_check_rg, mock_create_sg):
        mock_check_rg.side_effect = azure_mock.get_fake_resource_group
        mock_create_sg.side_effect = azure_mock.create_anything
        self.assertIsNone(self.driver._create_secgrp(
            security_group={"id": "fake_sg_id"}))
        mock_create_sg.assert_called_once_with(
            self.driver.network_client, azure_conf.resource_group,
            "secgrp-fake_sg_id", {"location": "eastus"})

    @mock.patch("neutron.common.azure.utils.delete_sg")
    @mock.patch(
        "neutron.common.azure.utils.check_resource_existence")
    def test_delete_sg(self, mock_check_rg, mock_delete_sg):
        mock_check_rg.side_effect = azure_mock.get_fake_resource_group
        mock_delete_sg.side_effect = azure_mock.delete_anything
        self.assertIsNone(self.driver._delete_secgrp(
            security_group_id="fake_sg_id"))
        mock_delete_sg.assert_called_once_with(
            self.driver.network_client, azure_conf.resource_group,
            "secgrp-fake_sg_id")

    @mock.patch(
        "neutron.common.azure.utils.check_resource_existence")
    def test_validate_secrule_with_ipv6_ethertype(self, mock_check_rg):
        mock_check_rg.side_effect = azure_mock.get_fake_resource_group
        sg_rule = self.get_fake_sg_rule(ethertype="IPv6")
        self.assertRaises(sg.SecurityGroupRuleInvalidEtherType,
                          self.driver._validate_secrule,
                          security_group_rule=sg_rule)

    @mock.patch(
        "neutron.common.azure.utils.check_resource_existence")
    def test_validate_secrule_with_invalid_protocol(self, mock_check_rg):
        mock_check_rg.side_effect = azure_mock.get_fake_resource_group
        sg_rule = self.get_fake_sg_rule(protocol="fake_protocol")
        self.assertRaises(
            sg.SecurityGroupRuleInvalidProtocol, self.driver._validate_secrule,
            security_group_rule=sg_rule)
