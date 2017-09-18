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

import boto
import mock

from moto import mock_ec2_deprecated
from nova import test
from nova.virt.ec2.keypair import KeyPairNotifications


class KeyPairNotificationsTestCase(test.NoDBTestCase):
    @mock_ec2_deprecated
    def setUp(self):
        super(KeyPairNotificationsTestCase, self).setUp()
        fake_access_key = 'aws_access_key'
        fake_secret_key = 'aws_secret_key'
        region_name = 'us-west-1'
        region = boto.ec2.get_region(region_name)
        self.fake_aws_conn = boto.ec2.EC2Connection(
            aws_access_key_id=fake_access_key,
            aws_secret_access_key=fake_secret_key,
            region=region)
        self.flags(rabbit_port=5672)
        self.conn = KeyPairNotifications(self.fake_aws_conn,
                                         transport='memory')

    def test_handle_notification_create_event(self):
        body = {'event_type': 'keypair.create.start'}
        with mock.patch.object(boto.ec2.EC2Connection, 'delete_key_pair') \
                as mock_delete:
            self.conn.handle_notification(body, None)
            mock_delete.assert_not_called()

    def test_handle_notifications_no_event_type(self):
        body = {}
        with mock.patch.object(boto.ec2.EC2Connection, 'delete_key_pair') \
                as mock_delete:
            self.conn.handle_notification(body, None)
            mock_delete.assert_not_called()

    @mock_ec2_deprecated
    def test_handle_notifications_delete_key(self):
        fake_key_name = 'fake_key'
        fake_key_data = 'fake_key_data'
        self.fake_aws_conn.import_key_pair(fake_key_name, fake_key_data)
        body = {'event_type': 'keypair.delete.start',
                'payload': {
                    'key_name': fake_key_name
                    }
                }
        self.conn.handle_notification(body, None)
        aws_keypairs = self.fake_aws_conn.get_all_key_pairs()
        self.assertEqual(len(aws_keypairs), 0)

    @mock_ec2_deprecated
    def test_handle_notifications_delete_key_with_multiple_keys_in_aws(self):
        fake_key_name_1 = 'fake_key_1'
        fake_key_data_1 = 'fake_key_data_1'
        fake_key_name_2 = 'fake_key_2'
        fake_key_data_2 = 'fake_key_data_2'
        self.fake_aws_conn.import_key_pair(fake_key_name_1, fake_key_data_1)
        self.fake_aws_conn.import_key_pair(fake_key_name_2, fake_key_data_2)
        body = {'event_type': 'keypair.delete.start',
                'payload': {
                    'key_name': fake_key_name_1
                    }
                }
        self.conn.handle_notification(body, None)
        aws_keypairs = self.fake_aws_conn.get_all_key_pairs()
        self.assertEqual(len(aws_keypairs), 1)
        self.assertEqual(aws_keypairs[0].name, fake_key_name_2)
