"""
Copyright 2016 Platform9 Systems Inc.
All Rights Reserved.
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
import boto3
import mock

from credsmgrclient.common.exceptions import HTTPBadGateway
from moto import mock_ec2
from nova import test
from nova.virt.ec2.notifications_handler import NovaNotificationsHandler


class NovaNotificationsTestCase(test.NoDBTestCase):
    @mock_ec2
    def setUp(self):
        super(NovaNotificationsTestCase, self).setUp()
        self.fake_access_key = 'aws_access_key'
        self.fake_secret_key = 'aws_secret_key'
        self.region_name = 'us-east-1',
        self.az = 'us-east-1a',
        self.flags(access_key=self.fake_access_key,
                   secret_key=self.fake_secret_key,
                   # Region name cannot be fake
                   region_name=self.region_name,
                   az=self.az,
                   group='AWS')
        self.fake_aws_conn = boto3.client(
            "ec2", aws_access_key_id=self.fake_access_key,
            aws_secret_access_key=self.fake_secret_key,
            region_name=self.region_name)
        self.flags(transport_url='memory://')
        self.conn = NovaNotificationsHandler()

    def test_handle_notification_create_event(self):
        body = {'event_type': 'keypair.create.start'}
        with mock.patch.object(self.fake_aws_conn, 'delete_key_pair') \
                as mock_delete:
            self.conn.handle_notification(body, None)
            mock_delete.assert_not_called()

    def test_handle_notifications_no_event_type(self):
        body = {}
        with mock.patch.object(self.fake_aws_conn, 'delete_key_pair') \
                as mock_delete:
            self.conn.handle_notification(body, None)
            mock_delete.assert_not_called()

    @mock_ec2
    @mock.patch('nova.virt.ec2.keypair._get_ec2_conn')
    @mock.patch('nova.virt.ec2.credshelper._get_credsmgr_client')
    def test_handle_notifications_delete_key(
            self, mock_credsmgr_client, mock_ec2_conn):
        mock_ec2_conn.return_value = self.fake_aws_conn
        mock_credsmgr_client.side_effect = HTTPBadGateway()
        fake_key_name = 'fake_key'
        fake_key_data = 'fake_key_data'
        self.fake_aws_conn.import_key_pair(
            KeyName=fake_key_name, PublicKeyMaterial=fake_key_data)
        body = {'event_type': 'keypair.delete.start',
                'payload': {
                    'key_name': fake_key_name
                    }
                }
        self.conn.handle_notification(body, None)
        aws_keypairs = self.fake_aws_conn.describe_key_pairs()
        self.assertEqual(len(aws_keypairs['KeyPairs']), 0)

    @mock_ec2
    @mock.patch('nova.virt.ec2.keypair._get_ec2_conn')
    @mock.patch('nova.virt.ec2.credshelper._get_credsmgr_client')
    def test_handle_notifications_delete_key_with_multiple_keys_in_aws(
            self, mock_credsmgr_client, mock_ec2_conn):
        mock_ec2_conn.return_value = self.fake_aws_conn
        mock_credsmgr_client.side_effect = HTTPBadGateway()
        fake_key_name_1 = 'fake_key_1'
        fake_key_data_1 = 'fake_key_data_1'
        fake_key_name_2 = 'fake_key_2'
        fake_key_data_2 = 'fake_key_data_2'
        self.fake_aws_conn.import_key_pair(
            KeyName=fake_key_name_1, PublicKeyMaterial=fake_key_data_1)
        self.fake_aws_conn.import_key_pair(
            KeyName=fake_key_name_2, PublicKeyMaterial=fake_key_data_2)
        body = {'event_type': 'keypair.delete.start',
                'payload': {
                    'key_name': fake_key_name_1
                    }
                }
        self.conn.handle_notification(body, None)
        aws_keypairs = self.fake_aws_conn.describe_key_pairs()
        self.assertEqual(len(aws_keypairs['KeyPairs']), 1)
        self.assertEqual(aws_keypairs[0]['Name'], fake_key_name_2)
