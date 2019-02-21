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

import base64
import contextlib

import boto3
import mock

from moto import mock_ec2
from oslo_log import log as logging
from oslo_utils import uuidutils

from credsmgrclient.common.exceptions import HTTPBadGateway
from nova.compute import task_states
from nova import context
from nova import exception
from nova.image.glance import GlanceImageServiceV2
from nova import objects
from nova import test
from nova.tests.unit import fake_instance
from nova.tests.unit import matchers
from nova.virt.ec2 import EC2Driver

LOG = logging.getLogger(__name__)

keypair_exist_response = {
    'KeyPairs': [
        {
            'KeyName': 'fake_key',
            'KeyFingerprint': 'fake_key_data'
        },
        {
            'KeyName': 'fake_key1',
            'KeyFingerprint': 'fake_key_data1'
        }
    ]
}


def fake_get_password(*args, **kwargs):
    return {'PasswordData': "Fake_encrypted_pass"}


class EC2DriverTestCase(test.NoDBTestCase):
    @mock_ec2
    def setUp(self):
        super(EC2DriverTestCase, self).setUp()
        self.fake_access_key = 'aws_access_key'
        self.fake_secret_key = 'aws_secret_key'
        self.region_name = 'us-east-1'
        self.az = 'us-east-1a'
        self.flags(access_key=self.fake_access_key,
                   secret_key=self.fake_secret_key,
                   # Region name cannot be fake
                   region_name=self.region_name,
                   az=self.az,
                   group='AWS')
        self.flags(api_servers=['http://localhost:9292'], group='glance')
        self.flags(transport_url='memory://')
        self.conn = EC2Driver(None, False)
        self.type_data = None
        self.project_id = 'fake'
        self.user_id = 'fake'
        self.instance_node = None
        self.uuid = None
        self.instance = None
        self.context = context.RequestContext(self.user_id, self.project_id)
        self.fake_ec2_conn = boto3.client(
            "ec2", aws_access_key_id=self.fake_access_key,
            aws_secret_access_key=self.fake_secret_key,
            region_name=self.region_name)

    def tearDown(self):
        super(EC2DriverTestCase, self).tearDown()

    @mock_ec2
    def reset(self):
        instance_list = self.fake_ec2_conn.describe_instances()
        # terminated instances are considered deleted and hence ignore them
        instance_id_list = []
        for reservation in instance_list['Reservations']:
            instance = reservation['Instances'][0]
            if instance['State']['Name'] != 'terminated':
                instance_id_list.append(instance['InstanceId'])
        if len(instance_id_list) > 0:
            self.fake_ec2_conn.stop_instances(InstanceIds=instance_id_list,
                                              Force=True)
            self.fake_ec2_conn.terminate_instances(
                InstanceIds=instance_id_list)
        self.type_data = None
        self.instance = None
        self.uuid = None
        self.instance_node = None

    def _get_instance_flavor_details(self):
        return {'memory_mb': 2048.0,
                'root_gb': 0,
                'deleted_at': None,
                'name': 't2.small',
                'deleted': 0,
                'created_at': None,
                'ephemeral_gb': 0,
                'updated_at': None,
                'disabled': False,
                'vcpus': 1,
                'extra_specs': {},
                'swap': 0,
                'rxtx_factor': 1.0,
                'is_public': True,
                'flavorid': '1',
                'vcpu_weight': None,
                'id': 2}

    def get_bdm(self):
        return {'/dev/sdf': {}, '/dev/sdg': {}, '/dev/sdh': {}, '/dev/sdi': {},
                '/dev/sdj': {}, '/dev/sdk': {}, '/dev/sdl': {}, '/dev/sdm': {},
                '/dev/sdn': {}, '/dev/sdo': {}, '/dev/sdp': {}}

    def _create_instance(self, key_name=None, key_data=None, user_data=None,
                         metadata={}):
        uuid = uuidutils.generate_uuid()
        self.type_data = self._get_instance_flavor_details()
        values = {'name': 'fake_instance',
                  'id': 1,
                  'uuid': uuid,
                  'project_id': self.project_id,
                  'user_id': self.user_id,
                  'kernel_id': 'fake_kernel_id',
                  'ramdisk_id': 'fake_ramdisk_id',
                  'flavor': objects.flavor.Flavor(**self.type_data),
                  'node': 'fake_node',
                  'memory_mb': self.type_data['memory_mb'],
                  'root_gb': self.type_data['root_gb'],
                  'ephemeral_gb': self.type_data['ephemeral_gb'],
                  'vpcus': self.type_data['vcpus'],
                  'swap': self.type_data['swap'],
                  'expected_attrs': ['system_metadata', 'metadata'],
                  'display_name': 'fake_instance',
                  'metadata': metadata}
        if key_name and key_data:
            values['key_name'] = key_name
            values['key_data'] = key_data
        if user_data:
            values['user_data'] = user_data
        self.instance_node = 'fake_node'
        self.uuid = uuid
        self.instance = fake_instance.fake_instance_obj(self.context, **values)

    def _create_network(self):
        self.vpc = self.fake_ec2_conn.create_vpc(CidrBlock='192.168.10.0/24')
        self.subnet = self.fake_ec2_conn.create_subnet(
            VpcId=self.vpc['Vpc']['VpcId'], CidrBlock='192.168.10.0/24',
            AvailabilityZone=self.az)
        self.subnet_id = self.subnet['Subnet']['SubnetId']

    def _create_nova_vm(self):
        with contextlib.nested(
            mock.patch.object(self.fake_ec2_conn, 'get_password_data'),
        ) as (mock_password_data):
            mock_password_data[0].side_effect = fake_get_password
            self.conn.spawn(self.context, self.instance, None,
                            injected_files=[], admin_password=None,
                            network_info=None, block_device_info=None)

    def _create_vm_in_aws_nova(self):
        self._create_instance()
        self._create_network()
        with contextlib.nested(
            mock.patch.object(EC2Driver, '_get_image_ami_id_from_meta'),
            mock.patch.object(EC2Driver, '_process_network_info'),
            mock.patch.object(EC2Driver, '_get_instance_sec_grps'),
        ) as (mock_image, mock_network, mock_secgrp):
            mock_image.return_value = 'ami-1234abc'
            mock_network.return_value = (self.subnet_id, '192.168.10.5', None,
                                         None, [])
            mock_secgrp.return_value = []
            self._create_nova_vm()

    @mock_ec2
    @mock.patch('nova.virt.ec2.credshelper._get_credsmgr_client')
    def test_list_instances(self, mock_credsmgr_client):
        for _ in range(0, 5):
            self.fake_ec2_conn.run_instances(ImageId='ami-1234abc', MinCount=1,
                                             MaxCount=1)
        mock_credsmgr_client.side_effect = HTTPBadGateway()
        fake_list = self.conn.list_instances()
        self.assertEqual(5, len(fake_list))
        self.reset()

    @mock_ec2
    def test_add_ssh_keys_key_exists(self):
        fake_key = 'fake_key'
        fake_key_data = 'abcdefgh'
        self.fake_ec2_conn.import_key_pair(
            KeyName=fake_key, PublicKeyMaterial=fake_key_data)
        with contextlib.nested(
            mock.patch.object(self.fake_ec2_conn, 'describe_key_pairs'),
            mock.patch.object(self.fake_ec2_conn, 'import_key_pair'),
        ) as (fake_get, fake_import):
            fake_get.return_value = keypair_exist_response
            self.conn._add_ssh_keys(self.fake_ec2_conn, fake_key,
                                    fake_key_data)
            fake_get.assert_called_once_with(KeyNames=[fake_key])
            fake_import.assert_not_called()

    @mock_ec2
    def test_add_ssh_keys_key_absent(self):
        fake_key = 'fake_key'
        fake_key_data = 'abcdefgh'
        with contextlib.nested(
            mock.patch.object(self.fake_ec2_conn, 'describe_key_pairs'),
            mock.patch.object(self.fake_ec2_conn, 'import_key_pair'),
        ) as (fake_get, fake_import):
            fake_get.return_value = {'KeyPairs': []}
            self.conn._add_ssh_keys(self.fake_ec2_conn, fake_key,
                                    fake_key_data)
            fake_get.assert_called_once_with(KeyNames=[fake_key])
            fake_import.assert_called_once_with(
                KeyName=fake_key, PublicKeyMaterial=fake_key_data)

    def test_process_network_info(self):
        fake_network_info = [{
            'profile': {},
            'ovs_interfaceid': None,
            'preserve_on_delete': False,
            'network': {
                'bridge': None,
                'subnets': [{
                    'ips': [{'meta': {},
                             'version': 4,
                             'type': 'fixed',
                             'floating_ips': [],
                             'address': u'192.168.100.5'}],
                    'version': 4,
                    'meta': {},
                    'dns': [],
                    'routes': [],
                    'cidr': u'192.168.100.0/24',
                    'gateway': {'meta': {},
                                'version': 4,
                                'type': 'gateway',
                                'address': u'192.168.100.1'}}],
                'meta': {'injected': True,
                         'tenant_id': '135b1a036a51414ea1f989ab59fefde5'},
                'id': '4f8ad58d-de60-4b52-94ba-8b988a9b7f33',
                'label': 'test'},
            'devname': 'tapa9a90cf6-62',
            'vnic_type': 'normal',
            'qbh_params': None,
            'meta': {},
            'details': '{"subnet_id": "subnet-0107db5a",'
                       ' "ip_address": "192.168.100.5",'
                       ' "ec2_security_groups": ["sg-123456"]}',
            'address': 'fa:16:3e:23:65:2c',
            'active': True,
            'type': 'vip_type_a',
            'id': 'a9a90cf6-627c-46f3-829d-c5a2ae07aaf0',
            'qbg_params': None
        }]
        aws_subnet_id, aws_fixed_ip, port_id, network_id, secgrps = \
            self.conn._process_network_info(fake_network_info)
        self.assertEqual(aws_subnet_id, 'subnet-0107db5a')
        self.assertEqual(aws_fixed_ip, '192.168.100.5')
        self.assertEqual(port_id, 'a9a90cf6-627c-46f3-829d-c5a2ae07aaf0')
        self.assertEqual(network_id, '4f8ad58d-de60-4b52-94ba-8b988a9b7f33')
        self.assertEqual(secgrps, ["sg-123456"])

    @mock_ec2
    def test_spawn(self):
        self._create_instance()
        self._create_network()
        with contextlib.nested(
            mock.patch.object(EC2Driver, '_get_image_ami_id_from_meta'),
            mock.patch.object(EC2Driver, '_process_network_info'),
            mock.patch.object(EC2Driver, '_get_instance_sec_grps'),
        ) as (mock_image, mock_network, mock_secgrp):
            mock_image.return_value = 'ami-1234abc'
            mock_network.return_value = (self.subnet_id, '192.168.10.5', None,
                                         None, [])
            mock_secgrp.return_value = []
            self._create_nova_vm()
            fake_instances = self.fake_ec2_conn.describe_instances()
            self.assertEqual(len(fake_instances['Reservations']), 1)
            self.assertEqual(
                len(fake_instances['Reservations'][0]['Instances']), 1)
            inst = fake_instances['Reservations'][0]['Instances'][0]
            self.assertEqual(inst['VpcId'], self.vpc['Vpc']['VpcId'])
            self.assertEqual(inst['SubnetId'], self.subnet_id)
            self.assertEqual(inst['ImageId'], 'ami-1234abc')
            self.assertEqual(inst['KeyName'], 'None')
            self.assertEqual(inst['InstanceType'], 't2.small')
            for tag in inst['Tags']:
                if tag['Key'] == 'Name':
                    self.assertEqual(tag['Value'], 'fake_instance')
                if tag['Key'] == "openstack_id":
                    self.assertEqual(tag['Value'], self.uuid)
        self.reset()

    @mock_ec2
    def test_spawn_with_key(self):
        self._create_instance(key_name='fake_key', key_data='fake_key_data')
        self._create_network()
        with contextlib.nested(
            mock.patch.object(EC2Driver, '_get_image_ami_id_from_meta'),
            mock.patch.object(EC2Driver, '_process_network_info'),
            mock.patch.object(EC2Driver, '_get_instance_sec_grps'),
        ) as (mock_image, mock_network, mock_secgrp):
            mock_image.return_value = 'ami-1234abc'
            mock_network.return_value = (self.subnet_id, '192.168.10.5', None,
                                         None, [])
            mock_secgrp.return_value = []
            self._create_nova_vm()
            fake_instances = self.fake_ec2_conn.describe_instances()
            self.assertEqual(len(fake_instances['Reservations']), 1)
            self.assertEqual(
                len(fake_instances['Reservations'][0]['Instances']), 1)
            inst = fake_instances['Reservations'][0]['Instances'][0]
            self.assertEqual(inst['KeyName'], 'fake_key')
        self.reset()

    @mock_ec2
    def test_spawn_with_userdata(self):
        userdata = '''
        #cloud-config
        password: password
        '''
        b64encoded = base64.b64encode(userdata)
        self._create_instance(user_data=b64encoded)
        self._create_network()
        with contextlib.nested(
            mock.patch.object(EC2Driver, '_get_image_ami_id_from_meta'),
            mock.patch.object(EC2Driver, '_process_network_info'),
            mock.patch.object(EC2Driver, '_get_instance_sec_grps'),
            mock.patch.object(EC2Driver, '_ec2_conn'),
        ) as (mock_image, mock_network, mock_secgrp, mock_ec2_conn):
            mock_image.return_value = 'ami-1234abc'
            mock_network.return_value = (self.subnet_id, '192.168.10.5', None,
                                         None, [])
            mock_secgrp.return_value = []
            mock_ec2_conn.return_value = self.fake_ec2_conn
            fake_run_instance_op = self.fake_ec2_conn.run_instances(
                ImageId='ami-1234abc', MaxCount=1, MinCount=1)
            self.fake_ec2_conn.run_instances = mock.Mock()
            self.fake_ec2_conn.run_instances.return_value = \
                fake_run_instance_op
            self._create_nova_vm()
            fake_instances = self.fake_ec2_conn.describe_instances()
            self.assertEqual(len(fake_instances['Reservations']), 1)
            self.fake_ec2_conn.run_instances.assert_called_once_with(
                InstanceType='t2.small', ImageId='ami-1234abc', MaxCount=1,
                UserData=userdata, SubnetId=self.subnet_id, MinCount=1,
                PrivateIpAddress='192.168.10.5', SecurityGroupIds=[])
        self.reset()

    @mock_ec2
    def test_spawn_with_metadata(self):
        metadata = {"key": "value"}
        self._create_instance(metadata=metadata)
        self._create_network()
        with contextlib.nested(
            mock.patch.object(EC2Driver, '_get_image_ami_id_from_meta'),
            mock.patch.object(EC2Driver, '_process_network_info'),
            mock.patch.object(EC2Driver, '_get_instance_sec_grps'),
            mock.patch.object(EC2Driver, '_ec2_conn'),
        ) as (mock_image, mock_network, mock_secgrp, mock_ec2_conn):
            mock_image.return_value = 'ami-1234abc'
            mock_network.return_value = (self.subnet_id, '192.168.10.5', None,
                                         None, [])
            mock_secgrp.return_value = []
            mock_ec2_conn.return_value = self.fake_ec2_conn
            fake_run_instance_op = self.fake_ec2_conn.run_instances(
                ImageId='ami-1234abc', MaxCount=1, MinCount=1)
            self.fake_ec2_conn.run_instances = mock.Mock()
            self.fake_ec2_conn.run_instances.return_value = \
                fake_run_instance_op
            self._create_nova_vm()
            fake_instances = self.fake_ec2_conn.describe_instances()
            self.assertEqual(len(fake_instances['Reservations']), 1)
            self.fake_ec2_conn.run_instances.assert_called_once_with(
                InstanceType='t2.small', ImageId='ami-1234abc',
                SubnetId=self.subnet_id, PrivateIpAddress='192.168.10.5',
                SecurityGroupIds=[], MaxCount=1, MinCount=1)
            for reservation in fake_instances['Reservations']:
                instance = reservation['Instances'][0]
                for tag in instance['Tags']:
                    if tag['Key'] == 'key':
                        self.assertEqual(tag['Value'], 'value')
        self.reset()

    @mock_ec2
    def test_spawn_with_network_error(self):
        self._create_instance()
        with contextlib.nested(
            mock.patch.object(EC2Driver, '_get_image_ami_id_from_meta'),
            mock.patch.object(EC2Driver, '_process_network_info'),
            mock.patch.object(EC2Driver, '_get_instance_sec_grps'),
        ) as (mock_image, mock_network, mock_secgrp):
            mock_image.return_value = 'ami-1234abc'
            mock_network.return_value = (None, None, None, None, [])
            mock_secgrp.return_value = []
            self.assertRaises(exception.BuildAbortException,
                              self._create_nova_vm)
        self.reset()

    @mock_ec2
    def test_spawn_with_network_error_from_aws(self):
        self._create_instance()
        with contextlib.nested(
            mock.patch.object(EC2Driver, '_get_image_ami_id_from_meta'),
            mock.patch.object(EC2Driver, '_process_network_info'),
            mock.patch.object(EC2Driver, '_get_instance_sec_grps'),
        ) as (mock_image, mock_network, mock_secgrp):
            mock_image.return_value = 'ami-1234abc'
            mock_network.return_value = (None, '192.168.10.5', None, None, [])
            mock_secgrp.return_value = []
            self.assertRaises(exception.BuildAbortException,
                              self._create_nova_vm)
        self.reset()

    @mock_ec2
    def test_spawn_with_image_error(self):
        self._create_instance()
        self._create_network()
        with contextlib.nested(
            mock.patch.object(EC2Driver, '_get_image_ami_id_from_meta'),
            mock.patch.object(EC2Driver, '_process_network_info'),
            mock.patch.object(EC2Driver, '_get_instance_sec_grps'),
        ) as (mock_image, mock_network, mock_secgrp):
            mock_image.side_effect = exception.BuildAbortException('fake')
            mock_network.return_value = ('subnet-1234abc', '192.168.10.5',
                                         None, None)
            mock_secgrp.return_value = []
            self.assertRaises(exception.BuildAbortException,
                              self._create_nova_vm)
        self.reset()

    @mock_ec2
    def test_snapshot(self):
        self._create_vm_in_aws_nova()
        GlanceImageServiceV2.update = mock.Mock()
        expected_calls = [{'args': (),
                           'kwargs': {
                               'task_state': task_states.IMAGE_UPLOADING,
                               'expected_state': task_states.IMAGE_SNAPSHOT}}]
        func_call_matcher = matchers.FunctionCallMatcher(expected_calls)
        self.conn.snapshot(self.context, self.instance, 'test-snapshot',
                           func_call_matcher.call)
        self.assertIsNone(func_call_matcher.match())
        _, snapshot_name, metadata = GlanceImageServiceV2.update.call_args[0]
        aws_imgs = self.fake_ec2_conn.describe_images(Owners=['self'])
        self.assertEqual(1, len(aws_imgs['Images']))
        aws_img = aws_imgs['Images'][0]
        self.assertEqual(snapshot_name, 'test-snapshot')
        self.assertEqual(aws_img['Name'], 'test-snapshot')
        self.assertEqual(aws_img['ImageId'],
                         metadata['properties']['ec2_image_id'])
        self.reset()

    @mock_ec2
    def test_snapshot_instance_not_found(self):
        self.fake_ec2_conn.create_image = mock.Mock()
        self._create_instance()
        GlanceImageServiceV2.update = mock.Mock()
        expected_calls = [{'args': (),
                           'kwargs': {
                               'task_state': task_states.IMAGE_UPLOADING,
                               'expected_state': task_states.IMAGE_SNAPSHOT}}]
        func_call_matcher = matchers.FunctionCallMatcher(expected_calls)
        self.assertRaises(exception.InstanceNotFound, self.conn.snapshot,
                          self.context, self.instance, 'test-snapshot',
                          func_call_matcher.call)
        self.fake_ec2_conn.create_image.assert_not_called()
        self.reset()

    @mock_ec2
    def test_reboot_soft(self):
        self._create_vm_in_aws_nova()
        self.assertIsNone(self.conn.reboot(self.context, self.instance, None,
                                           'SOFT', None, None))
        self.reset()

    @mock_ec2
    def test_reboot_hard(self):
        self._create_vm_in_aws_nova()
        fake_instances = self.fake_ec2_conn.describe_instances()
        fake_inst = fake_instances['Reservations'][0]['Instances'][0]
        EC2Driver._wait_for_state = mock.Mock()
        self.assertIsNone(self.conn.reboot(self.context, self.instance, None,
                                           'HARD', None, None))
        wait_state_calls = EC2Driver._wait_for_state.call_args_list
        LOG.info(wait_state_calls)
        self.assertEqual(2, len(wait_state_calls))
        self.assertEqual('stopped', wait_state_calls[0][0][3])
        self.assertEqual(fake_inst['InstanceId'], wait_state_calls[0][0][2])
        self.assertEqual('running', wait_state_calls[1][0][3])
        self.assertEqual(fake_inst['InstanceId'], wait_state_calls[1][0][2])
        self.reset()

    @mock_ec2
    def test_reboot_instance_not_found(self):
        self._create_instance()
        self.fake_ec2_conn.stop_instances = mock.Mock()
        self.assertRaises(exception.InstanceNotFound, self.conn.reboot,
                          self.context, self.instance, None, 'SOFT', None,
                          None)
        self.fake_ec2_conn.stop_instances.assert_not_called()
        self.reset()

    @mock_ec2
    def test_power_off(self):
        self._create_vm_in_aws_nova()
        fake_instances = self.fake_ec2_conn.describe_instances()
        fake_inst = fake_instances['Reservations'][0]['Instances'][0]
        self.assertEqual(fake_inst['State']['Name'], 'running')
        with contextlib.nested(
            mock.patch.object(EC2Driver, '_ec2_conn'),
        ) as (mock_ec2_conn,):
            mock_ec2_conn.return_value = self.fake_ec2_conn
            self.conn.power_off(self.instance)
        fake_instances = self.fake_ec2_conn.describe_instances()
        fake_inst = fake_instances['Reservations'][0]['Instances'][0]
        self.assertEqual(fake_inst['State']['Name'], 'stopped')
        self.reset()

    @mock_ec2
    def test_power_off_instance_not_found(self):
        self._create_instance()
        self.assertRaises(exception.InstanceNotFound, self.conn.power_off,
                          self.instance)
        self.reset()

    @mock_ec2
    def test_power_on(self):
        self._create_vm_in_aws_nova()
        fake_instances = self.fake_ec2_conn.describe_instances()
        fake_inst = fake_instances['Reservations'][0]['Instances'][0]
        self.fake_ec2_conn.stop_instances(
            InstanceIds=[fake_inst['InstanceId']])
        self.conn.power_on(self.context, self.instance, None, None)
        fake_instances = self.fake_ec2_conn.describe_instances()
        fake_inst = fake_instances['Reservations'][0]['Instances'][0]
        self.assertEqual(fake_inst['State']['Name'], 'running')
        self.reset()

    @mock_ec2
    def test_power_on_instance_not_found(self):
        self._create_instance()
        self.assertRaises(exception.InstanceNotFound, self.conn.power_on,
                          self.context, self.instance, None, None)
        self.reset()

    @mock_ec2
    def test_destroy(self):
        self._create_vm_in_aws_nova()
        self.conn.destroy(self.context, self.instance, None, None)
        fake_instances = self.fake_ec2_conn.describe_instances()
        fake_inst = fake_instances['Reservations'][0]['Instances'][0]
        self.assertEqual(fake_inst['State']['Name'], 'terminated')
        self.reset()

    @mock_ec2
    def test_destroy_instance_not_found(self):
        self._create_instance()
        with contextlib.nested(
            mock.patch.object(self.fake_ec2_conn, 'stop_instances'),
            mock.patch.object(self.fake_ec2_conn, 'terminate_instances'),
            mock.patch.object(EC2Driver, '_wait_for_state'),
        ) as (fake_stop, fake_terminate, fake_wait):
            self.assertRaises(exception.InstanceNotFound, self.conn.destroy,
                              self.context, self.instance, None, None)
            fake_stop.assert_not_called()
            fake_terminate.assert_not_called()
            fake_wait.assert_not_called()
        self.reset()

    @mock_ec2
    def test_destory_instance_terminated_on_aws(self):
        self._create_vm_in_aws_nova()
        fake_instances = self.fake_ec2_conn.describe_instances()
        fake_inst = fake_instances['Reservations'][0]['Instances'][0]
        inst_id = fake_inst['InstanceId']
        self.fake_ec2_conn.stop_instances(InstanceIds=[inst_id])
        self.fake_ec2_conn.terminate_instances(InstanceIds=[inst_id])
        with contextlib.nested(
            mock.patch.object(self.fake_ec2_conn, 'stop_instances'),
            mock.patch.object(self.fake_ec2_conn, 'terminate_instances'),
            mock.patch.object(EC2Driver, '_wait_for_state'),
        ) as (fake_stop, fake_terminate, fake_wait):
            self.conn.destroy(self.context, self.instance, None, None)
            fake_stop.assert_not_called()
            fake_terminate.assert_not_called()
            fake_wait.assert_not_called()
        self.reset()

    @mock_ec2
    @mock.patch.object(EC2Driver, '_ec2_conn')
    def test_destroy_instance_shut_down_on_aws(self, mock_ec2_conn):
        mock_ec2_conn.return_value = self.fake_ec2_conn
        self._create_vm_in_aws_nova()
        fake_instances = self.fake_ec2_conn.describe_instances()
        fake_inst = fake_instances['Reservations'][0]['Instances'][0]
        inst_id = fake_inst['InstanceId']
        self.fake_ec2_conn.stop_instances(InstanceIds=[inst_id])
        with contextlib.nested(
            mock.patch.object(self.fake_ec2_conn, 'stop_instances'),
            mock.patch.object(self.fake_ec2_conn, 'terminate_instances'),
            mock.patch.object(EC2Driver, '_wait_for_state'),
        ) as (fake_stop, fake_terminate, fake_wait):
            self.conn.destroy(self.context, self.instance, None, None)
            fake_stop.assert_not_called()
            fake_terminate.assert_called_once_with(InstanceIds=[inst_id])
        self.reset()

    @mock_ec2
    def test_get_info(self):
        self._create_vm_in_aws_nova()
        vm_info = self.conn.get_info(self.instance)
        self.assertEqual(0, vm_info.state)
        self.reset()

    @mock_ec2
    def test_get_info_instance_not_found(self):
        self._create_instance()
        self.assertRaises(exception.InstanceNotFound, self.conn.get_info,
                          self.instance)
        self.reset()

    @mock_ec2
    @mock.patch('nova.virt.ec2.credshelper._get_credsmgr_client')
    def test_get_device_name_for_instance(self, mock_credsmgr_client):
        mock_credsmgr_client.side_effect = HTTPBadGateway()
        self._create_vm_in_aws_nova()
        block_device_name = self.conn.get_device_name_for_instance(
            self.instance, None, None)
        self.assertEqual(block_device_name, "/dev/sdf")

    @mock_ec2
    def test_get_device_name_for_instance_failure(self):
        self._create_instance()
        self.instance.block_device_mapping = self.get_bdm()
        self.assertRaises(exception.NovaException,
                          self.conn.get_device_name_for_instance,
                          self.instance, None, None)

    @mock_ec2
    def test_change_instance_metadata_add_metadata(self):
        self._create_vm_in_aws_nova()
        diff = {"key": ["+", "value"]}
        self.conn.change_instance_metadata(self.context, self.instance, diff)
        fake_instances = self.fake_ec2_conn.describe_instances()
        fake_inst = fake_instances['Reservations'][0]['Instances'][0]
        for tag in fake_inst['Tags']:
            if tag['Key'] == "key":
                self.assertEqual(tag['Value'], "value")

    @mock_ec2
    def test_change_instance_metadata_remove_metadata(self):
        self._create_vm_in_aws_nova()
        diff = {"key": ["+", "value"]}
        self.conn.change_instance_metadata(self.context, self.instance, diff)
        diff = {"key": ["-"]}
        self.conn.change_instance_metadata(self.context, self.instance, diff)
        fake_instances = self.fake_ec2_conn.describe_instances()
        fake_inst = fake_instances['Reservations'][0]['Instances'][0]
        key_present = False
        for tag in fake_inst['Tags']:
            if tag['Key'] == 'key':
                key_present = True
        self.assertFalse(key_present)

    @mock_ec2
    def test_change_instance_metadata_bulk_add_metadata(self):
        self._create_vm_in_aws_nova()
        diff = {
            "key1": ["+", "value1"],
            "key2": ["+", "value2"]
        }
        self.conn.change_instance_metadata(self.context, self.instance, diff)
        fake_instances = self.fake_ec2_conn.describe_instances()
        fake_inst = fake_instances['Reservations'][0]['Instances'][0]
        for key, change in diff.items():
            for tag in fake_inst['Tags']:
                if tag['Key'] == key:
                    self.assertEqual(tag['Value'], change[1])

    @mock_ec2
    def test_change_instance_metadata_bulk_remove_metadata(self):
        self._create_vm_in_aws_nova()
        diff = {
            "key1": ["+", "value1"],
            "key2": ["+", "value2"]
        }
        self.conn.change_instance_metadata(self.context, self.instance, diff)
        reverse_diff = {k: ["-"] for k in diff.keys()}
        self.conn.change_instance_metadata(self.context, self.instance,
                                           reverse_diff)
        fake_instances = self.fake_ec2_conn.describe_instances()
        fake_inst = fake_instances['Reservations'][0]['Instances'][0]
        key_present = False
        for key, change in diff.items():
            for tag in fake_inst['Tags']:
                if tag['Key'] == key:
                    key_present = True
        self.assertFalse(key_present)
