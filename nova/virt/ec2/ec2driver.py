"""
Copyright (c) 2014 Thoughtworks.
Copyright (c) 2017 Platform9 Systems Inc.
All Rights reserved
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

import base64
import datetime
import eventlet
import hashlib
import json
import time
import uuid

import boto3

from botocore.exceptions import ClientError

from nova.compute import power_state
from nova.compute import task_states
from nova.console import type as ctype
from nova import exception
from nova.i18n import _
from nova.image import glance
from nova import network
from nova.virt import driver
from nova.virt.ec2.config import CONF
from nova.virt.ec2.config import EC2_FLAVOR_MAP
from nova.virt.ec2.config import EC2_STATE_MAP
from nova.virt.ec2.credshelper import get_credentials
from nova.virt.ec2.credshelper import get_credentials_all
from nova.virt.ec2.notifications_handler import NovaNotificationsHandler
from nova.virt.ec2 import vm_refs_cache
from nova.virt import hardware

from oslo_log import log as logging
from oslo_service import loopingcall

eventlet.monkey_patch()

LOG = logging.getLogger(__name__)

_EC2_NODES = None

DIAGNOSTIC_KEYS_TO_FILTER = ['SecurityGroups', 'BlockDeviceMappings']


def set_nodes(nodes):
    """Sets EC2Driver's node.list.

    It has effect on the following methods:
        get_available_nodes()
        get_available_resource
        get_host_stats()

    To restore the change, call restore_nodes()
    """
    global _EC2_NODES
    _EC2_NODES = nodes


def restore_nodes():
    """Resets EC2Driver's node list modified by set_nodes().

    Usually called from tearDown().
    """
    global _EC2_NODES
    _EC2_NODES = [CONF.host]


def _get_ec2_client(creds, service):
    ec2_conn = boto3.client(
        service, region_name=CONF.AWS.region_name,
        aws_access_key_id=creds['aws_access_key_id'],
        aws_secret_access_key=creds['aws_secret_access_key'])
    return ec2_conn


def get_all_ec2_instances_volumes():
    credentials = get_credentials_all()
    zone_filter = [{'Name': 'availability-zone', 'Values': [CONF.AWS.az]}]
    for creds in credentials:
        project_id = creds.get('project_id')
        ec2_conn = _get_ec2_client(creds, "ec2")
        volume_ids = []
        instance_list = []
        try:
            instance_list = ec2_conn.describe_instances(Filters=zone_filter)
            for reservation in instance_list['Reservations']:
                instance = reservation['Instances'][0]
                volume_ids.extend([bdm['Ebs']['VolumeId']
                                   for bdm in instance['BlockDeviceMappings']])
                if instance['State']['Name'] in ['pending', 'shutting-down',
                                                 'terminated']:
                    continue
                instance['Tags'].append({
                    'Key': 'project_id',
                    'Value': project_id})
                yield 'instance', instance
        except ClientError as e:
            LOG.exception("Error while getting instances: %s", e.message)
        if len(volume_ids):
            try:
                volumes = ec2_conn.describe_volumes(VolumeIds=volume_ids)
                for volume in volumes['Volumes']:
                    yield 'volume', volume
            except ClientError as e:
                LOG.exception("Error while getting volumes: %s", e.message)


def convert_password(password):
    """Stores password as system_metadata items.

    Password is stored with the keys 'password_0' -> 'password_3'.
    """
    CHUNKS = 4
    CHUNK_LENGTH = 255
    password = password or ''
    meta = {}
    for i in range(CHUNKS):
        meta['password_%d' % i] = password[:CHUNK_LENGTH]
        password = password[CHUNK_LENGTH:]
    return meta


class EC2Driver(driver.ComputeDriver):
    capabilities = {
        "has_imagecache": True,
        "supports_recreate": True,
    }

    def __init__(self, virtapi, read_only=False):
        super(EC2Driver, self).__init__(virtapi)
        self.host_status_base = {
            'vcpus': CONF.AWS.max_vcpus,
            'memory_mb': CONF.AWS.max_memory_mb,
            'local_gb': CONF.AWS.max_disk_gb,
            'vcpus_used': 0,
            'memory_mb_used': 0,
            'local_gb_used': 0,
            'hypervisor_type': 'EC2',
            'hypervisor_version': '1.0',
            'hypervisor_hostname': CONF.host,
            'cpu_info': {},
            'disk_available_least': CONF.AWS.max_disk_gb,
        }
        global _EC2_NODES
        self._mounts = {}
        self._interfaces = {}
        self._inst_vol_cache = {}
        self.ec2_flavor_info = EC2_FLAVOR_MAP
        self._local_instance_uuids = []
        self._driver_tags = [
            'openstack_id', 'openstack_project_id', 'openstack_user_id',
            'Name', 'project_id']

        # Allow keypair deletion to be controlled by conf
        if CONF.AWS.enable_keypair_notifications:
            eventlet.spawn(NovaNotificationsHandler().run)
        LOG.info("EC2 driver init with %s region" % CONF.AWS.region_name)
        if _EC2_NODES is None:
            set_nodes([CONF.host])
        # PF9 Start
        self._pf9_stats = {}
        # PF9 End

    def _ec2_conn(self, context=None, project_id=None):
        creds = get_credentials(context=context, project_id=project_id)
        return _get_ec2_client(creds, "ec2")

    def _cloudwatch_conn(self, context=None, project_id=None):
        creds = get_credentials(context=context, project_id=project_id)
        return _get_ec2_client(creds, "cloudwatch")

    def init_host(self, host):
        """Initialize anything that is necessary for the driver to function,
        including catching up with currently running VM's on the given host.
        """
        return

    def _get_details_from_tags(self, instance, field):
        if field == "openstack_id":
            value = self._get_uuid_from_aws_id(instance['InstanceId'])
        if field == "Name":
            value = "_NO_NAME_IN_AWS_"
        if field == "project_id":
            value = None
        for tag in instance['Tags']:
            if tag['Key'] == field:
                value = tag['Value']
        return value

    def list_instances(self):
        """Return the names of all the instances known to the virtualization
        layer, as a list.
        """
        all_instances_volumes = get_all_ec2_instances_volumes()
        instance_ids = []
        self._local_instance_uuids = []
        self._inst_vol_cache.clear()
        for obj_type, obj in all_instances_volumes:
            if obj_type == 'instance':
                os_id = self._get_details_from_tags(obj, 'openstack_id')
                vm_refs_cache.vm_ref_cache_update(os_id, obj)
                self._local_instance_uuids.append(os_id)
                instance_ids.append(obj['InstanceId'])
            elif obj_type == 'volume':
                self._inst_vol_cache[obj['VolumeId']] = obj
        return instance_ids

    def plug_vifs(self, instance, network_info):
        """Plug VIFs into networks."""
        pass

    def unplug_vifs(self, instance, network_info):
        """Unplug VIFs from networks."""
        pass

    def _add_ssh_keys(self, ec2_conn, key_name, key_data):
        """Adds SSH Keys into AWS EC2 account

        :param key_name:
        :param key_data:
        :return:
        """
        # TODO(add_ssh_keys): Need to handle the cases if a key with the same
        # keyname exists and different key content
        try:
            response = ec2_conn.describe_key_pairs(KeyNames=[key_name])
            if response['KeyPairs']:
                LOG.info("SSH key already exists in AWS")
                return
        except ClientError as e:
            LOG.warning('Error while calling describe_key_pairs: %s',
                        e.message)
        LOG.info("Adding SSH key to AWS")
        ec2_conn.import_key_pair(KeyName=key_name, PublicKeyMaterial=key_data)

    def _get_image_ami_id_from_meta(self, context, image_lacking_meta):
        """Pulls the Image AMI ID from the location attribute of Image Meta

        :param image_meta:
        :return: ami_id
        """
        image_api = glance.get_default_image_service()
        image_meta = image_api._client.call(context, 2, 'get',
                                            image_lacking_meta.id)
        LOG.info("Calling _get_image_ami_id_from_meta Meta: %s" % image_meta)
        try:
            return image_meta['aws_image_id']
        except Exception as e:
            LOG.error("Error in parsing Image Id: %s" % e)
            raise exception.BuildAbortException("Invalid or Non-Existent Image"
                                                " ID Error")

    def _process_network_info(self, network_info):
        """Will process network_info object by picking up only one Network out
        of many

        :param network_info:
        :return:
        """
        LOG.info("Networks to be processed : %s" % network_info)
        subnet_id = None
        fixed_ip = None
        port_id = None
        network_id = None
        security_group_ids = []
        if len(network_info) > 1:
            LOG.warn('AWS does not allow connecting 1 instance to multiple '
                     'VPCs.')
        for vif in network_info:
            if 'details' in vif:
                network_dict = json.loads(vif['details'])
                subnet_id = network_dict['subnet_id']
                LOG.info("Adding subnet ID:" + subnet_id)
                fixed_ip = network_dict['ip_address']
                security_group_ids = network_dict.get('ec2_security_groups',
                                                      [])
                LOG.info("Fixed IP:" + fixed_ip)
                port_id = vif['id']
                network_id = vif['network']['id']
                break
        return subnet_id, fixed_ip, port_id, network_id, security_group_ids

    def _get_instance_sec_grps(self, context, ec2_conn, port_id, network_id):
        secgrp_ids = []
        network_api = network.API()
        port_obj = network_api.show_port(context, port_id)
        if port_obj.get('port', {}).get('security_groups', []):
            filters = [{'Name': 'tag-value',
                        'Values': port_obj['port']['security_groups']}]
            secgrps = ec2_conn.describe_security_groups(Filters=filters)
            for secgrp in secgrps['SecurityGroups']:
                for tag in secgrp['Tags']:
                    if (tag['Key'] == 'openstack_network_id' and
                            tag['Value'] == network_id):
                        secgrp_ids.append(secgrp.id)
        return secgrp_ids

    def spawn(self, context, instance, image_meta, injected_files,
              admin_password, network_info=None, block_device_info=None):
        """Create a new instance/VM/domain on the virtualization platform.
        Once this successfully completes, the instance should be
        running (power_state.RUNNING).

        If this fails, any partial instance should be completely
        cleaned up, and the virtualization platform should be in the state
        that it was before this call began.

        :param context: security context <Not Yet Implemented>
        :param instance: nova.objects.instance.Instance
                         This function should use the data there to guide
                         the creation of the new instance.
        :param image_meta: image object returned by nova.image.glance that
                           defines the image from which to boot this instance
        :param injected_files: User files to inject into instance.
        :param admin_password: set in instance. <Not Yet Implemented>
        :param network_info:
           :py:meth:`~nova.network.manager.NetworkManager.get_instance_nw_info`
        :param block_device_info: Information about block devices to be
                                  attached to the instance.
        """
        ec2_conn = self._ec2_conn(context, project_id=instance.project_id)
        image_ami_id = self._get_image_ami_id_from_meta(context, image_meta)

        subnet_id, fixed_ip, port_id, network_id, security_group_ids = \
            self._process_network_info(network_info)
        if subnet_id is None or fixed_ip is None:
            raise exception.BuildAbortException("Network configuration "
                                                "failure")

        if len(security_group_ids) == 0:
            security_group_ids = self._get_instance_sec_grps(
                context, ec2_conn, port_id, network_id)
        # Flavor
        flavor_type = instance['flavor']['name']

        # SSH Keys
        if instance['key_name'] and instance['key_data']:
            self._add_ssh_keys(ec2_conn, instance['key_name'],
                               instance['key_data'])

        # Creating the EC2 instance
        user_data = None
        # Passing user_data from the openstack instance which is Base64 encoded
        # after decoding it.
        if 'user_data' in instance and instance['user_data'] is not None:
            user_data = instance['user_data']
            user_data = base64.b64decode(user_data)
        try:
            kwargs = dict(InstanceType=flavor_type, ImageId=image_ami_id,
                          SubnetId=subnet_id, PrivateIpAddress=fixed_ip,
                          SecurityGroupIds=security_group_ids, MaxCount=1,
                          MinCount=1)
            if user_data:
                kwargs.update({'UserData': user_data})
            if 'key_name' in instance and instance['key_name']:
                kwargs.update({'KeyName': instance['key_name']})
            reservation = ec2_conn.run_instances(**kwargs)
            ec2_instance_obj = reservation['Instances'][0]
            ec2_id = ec2_instance_obj['InstanceId']
            self._wait_for_state(ec2_conn, instance, ec2_id, "running",
                                 power_state.RUNNING, check_exists=True)
            ec2_tags = [
                {'Key': 'Name', 'Value': instance.display_name},
                {'Key': 'openstack_id', 'Value': instance.uuid},
                {'Key': 'openstack_project_id', 'Value': context.project_id},
                {'Key': 'openstack_user_id', 'Value': context.user_id}
            ]
            if instance.metadata:
                for key, value in instance.metadata.items():
                    if key.startswith('aws:'):
                        LOG.warn('Invalid EC2 tag. %s will be ignored', key)
                    else:
                        ec2_tags.append({'Key': key, 'Value': value})
            ec2_conn.create_tags(Resources=[ec2_id], Tags=ec2_tags)
            instance.metadata.update({'ec2_id': ec2_id})
            vm_refs_cache.vm_ref_cache_update(instance.uuid, ec2_instance_obj)

            # Fetch Public IP of the instance if it has one
            ec2_instances = ec2_conn.describe_instances(InstanceIds=[ec2_id])
            if len(ec2_instances['Reservations']) > 0:
                ec2_instance = ec2_instances['Reservations'][0]['Instances'][0]
                public_ip = None
                if 'PublicIpAddress' in ec2_instance:
                    public_ip = ec2_instance['PublicIpAddress']
                if public_ip:
                    instance['metadata'].update({
                        'public_ip_address': public_ip})
        except ClientError as ec2_exception:
            LOG.info("Error in starting instance %s" % (ec2_exception.message))
            raise exception.BuildAbortException(ec2_exception.message)

        eventlet.spawn_n(self._update_password, ec2_conn, ec2_id, instance)

    def _update_password(self, ec2_conn, ec2_id, openstack_instance):
        try:
            instance_pass = None
            retries = 0
            while not instance_pass:
                time.sleep(15)
                response = ec2_conn.get_password_data(InstanceId=ec2_id)
                instance_pass = response['PasswordData'].strip()
                retries += 1
                if retries == 10:
                    break
            if instance_pass:
                openstack_instance['system_metadata'].update(
                    convert_password(instance_pass))
                openstack_instance.save()
                LOG.info("Updated password for instance with ec2_id %s" %
                         (ec2_id))
            else:
                LOG.warn("Failed to get password for ec2 instance %s "
                         "after multiple tries" % (ec2_id))
        except (ClientError, NotImplementedError):
            # For Linux instances we get unauthorized exception
            # in get_password_data
            LOG.info("Get password operation is not supported "
                     "for ec2 instance %s" % (ec2_id))

    def _get_ec2_id_from_instance(self, instance):
        ec2_instance = vm_refs_cache.vm_ref_cache_get(instance.uuid)
        if ec2_instance:
            return ec2_instance['InstanceId']
        elif 'ec2_id' in instance.metadata and instance.metadata['ec2_id']:
            return instance.metadata['ec2_id']
        # if none of the conditions are met we cannot map OpenStack UUID to
        # AWS ID.
        raise exception.InstanceNotFound('Instance {0} not found'.format(
            instance.uuid))

    def snapshot(self, context, instance, image_id, update_task_state):
        """Snapshot an image of the specified instance on EC2 and create an
        Image which gets stored in AMI (internally in EBS Snapshot)

        :param context: security context
        :param instance: nova.objects.instance.Instance
        :param image_id: Reference to a pre-created image that will hold the
        snapshot.
        """
        ec2_conn = self._ec2_conn(context, project_id=instance.project_id)

        if instance.metadata.get('ec2_id', None) is None:
            raise exception.InstanceNotFound(instance_id=instance['uuid'])
        # Adding the below line only alters the state of the instance and not
        # its image in OpenStack.
        update_task_state(
            task_state=task_states.IMAGE_UPLOADING,
            expected_state=task_states.IMAGE_SNAPSHOT)
        ec2_id = self._get_ec2_id_from_instance(instance)
        ec2_instance_info = ec2_conn.describe_instances(InstanceIds=[ec2_id])
        ec2_instance = ec2_instance_info['Reservations'][0]['Instances'][0]
        if ec2_instance['State']['Name'] == 'running':
            response = ec2_conn.create_image(
                Name=str(image_id), Description="Image created by OpenStack",
                NoReboot=False, DryRun=False, InstanceId=ec2_id)
            ec2_image_id = response['ImageId']
            LOG.info("Image created: %s." % ec2_image_id)
        # The instance will be in pending state when it comes up, waiting
        # for it to be in available
        self._wait_for_image_state(ec2_conn, ec2_image_id, "available")

        image_api = glance.get_default_image_service()
        image_ref = glance.generate_image_url(image_id)

        metadata = {'is_public': False,
                    'location': image_ref,
                    'properties': {
                        'kernel_id': instance['kernel_id'],
                        'image_state': 'available',
                        'owner_id': instance['project_id'],
                        'ramdisk_id': instance['ramdisk_id'],
                        'ec2_image_id': ec2_image_id}}
        # TODO(jhurt): This currently fails, leaving the status of an instance
        #              as 'snapshotting'
        image_api.update(context, image_id, metadata)

    def reboot(self, context, instance, network_info, reboot_type,
               block_device_info=None, bad_volumes_callback=None):
        """
        Reboot the specified instance.
        After this is called successfully, the instance's state
        goes back to power_state.RUNNING. The virtualization
        platform should ensure that the reboot action has completed
        successfully even in cases in which the underlying domain/vm
        is paused or halted/stopped.

        :param instance: nova.objects.instance.Instance
        :param network_info:
           :py:meth:`~nova.network.manager.NetworkManager.get_instance_nw_info`
        :param reboot_type: Either a HARD or SOFT reboot
        :param block_device_info: Info pertaining to attached volumes
        :param bad_volumes_callback: Function to handle any bad volumes
        encountered
        """
        if reboot_type == 'SOFT':
            self._soft_reboot(
                context, instance, network_info, block_device_info)
        elif reboot_type == 'HARD':
            self._hard_reboot(
                context, instance, network_info, block_device_info)

    def _soft_reboot(self, context, instance, network_info,
                     block_device_info=None):
        ec2_conn = self._ec2_conn(context, project_id=instance.project_id)
        ec2_id = self._get_ec2_id_from_instance(instance)
        ec2_conn.reboot_instances(InstanceIds=[ec2_id], DryRun=False)
        LOG.info("Soft Reboot Complete.")

    def _hard_reboot(self, context, instance, network_info,
                     block_device_info=None):
        ec2_id = self._get_ec2_id_from_instance(instance)
        ec2_conn = self._ec2_conn(context, project_id=instance.project_id)
        ec2_conn.stop_instances(InstanceIds=[ec2_id], Force=False,
                                DryRun=False)
        self._wait_for_state(ec2_conn, instance, ec2_id, "stopped",
                             power_state.SHUTDOWN)
        ec2_conn.start_instances(InstanceIds=[ec2_id], DryRun=False)
        self._wait_for_state(ec2_conn, instance, ec2_id, "running",
                             power_state.RUNNING)
        LOG.info("Hard Reboot Complete.")

    @staticmethod
    def get_host_ip_addr():
        """Retrieves the IP address of the host"""
        return CONF.my_ip

    def set_admin_password(self, instance, new_pass):
        """Boto doesn't support setting the password at the time of creating an
        instance, hence not implemented.
        """
        pass

    def inject_file(self, instance, b64_path, b64_contents):
        pass

    def resume_state_on_host_boot(self, context, instance, network_info,
                                  block_device_info=None):
        pass

    def rescue(self, context, instance, network_info, image_meta,
               rescue_password):
        pass

    def unrescue(self, instance, network_info):
        pass

    def poll_rebooting_instances(self, timeout, instances):
        pass

    def migrate_disk_and_power_off(self, context, instance, dest,
                                   instance_type, network_info,
                                   block_device_info=None):
        pass

    def finish_revert_migration(self, context, instance, network_info,
                                block_device_info=None, power_on=True):
        pass

    def post_live_migration_at_destination(self, context, instance,
                                           network_info,
                                           block_migration=False,
                                           block_device_info=None):
        pass

    def power_off(self, instance, timeout=0, retry_interval=0):
        """Power off the specified instance.

        :param instance: nova.objects.instance.Instance
        :param timeout: time to wait for GuestOS to shutdown
        :param retry_interval: How often to signal guest while
                               waiting for it to shutdown
        """
        # TODO(timeout): Need to use timeout and retry_interval
        ec2_id = self._get_ec2_id_from_instance(instance)
        ec2_conn = self._ec2_conn(project_id=instance.project_id)
        ec2_conn.stop_instances(InstanceIds=[ec2_id], Force=False,
                                DryRun=False)
        self._wait_for_state(ec2_conn, instance, ec2_id, "stopped",
                             power_state.SHUTDOWN)

    def power_on(self, context, instance, network_info, block_device_info):
        """Power on the specified instance."""
        ec2_id = self._get_ec2_id_from_instance(instance)
        ec2_conn = self._ec2_conn(context, project_id=instance.project_id)
        ec2_conn.start_instances(InstanceIds=[ec2_id], DryRun=False)
        self._wait_for_state(ec2_conn, instance, ec2_id, "running",
                             power_state.RUNNING)

    def soft_delete(self, instance):
        """Deleting the specified instance"""
        self.destroy(instance)

    def restore(self, instance):
        pass

    def pause(self, instance):
        """Boto doesn't support pause and cannot save system state and hence
        we've implemented the closest functionality which is to poweroff the
        instance.

        :param instance: nova.objects.instance.Instance
        """
        self.power_off(instance)

    def unpause(self, instance):
        """Since Boto doesn't support pause and cannot save system state, we
        had implemented the closest functionality which is to poweroff the
        instance. and powering on such an instance in this method.

        :param instance: nova.objects.instance.Instance
        """
        self.power_on(context=None, instance=instance, network_info=None,
                      block_device_info=None)

    def suspend(self, context, instance):
        """Boto doesn't support suspend and cannot save system state and hence
        we've implemented the closest functionality which is to poweroff the
        instance.

        :param instance: nova.objects.instance.Instance
        """
        self.power_off(instance)

    def resume(self, context, instance, network_info, block_device_info=None):
        """Since Boto doesn't support suspend and we cannot save system state,
        we've implemented the closest functionality which is to power on the
        instance.

        :param instance: nova.objects.instance.Instance
        """
        self.power_on(context, instance, network_info, block_device_info)

    def destroy(self, context, instance, network_info, block_device_info=None,
                destroy_disks=True, migrate_data=None):
        """Destroy the specified instance from the Hypervisor.

        If the instance is not found (for example if networking failed), this
        function should still succeed.  It's probably a good idea to log a
        warning in that case.

        :param context: security context
        :param instance: Instance object as returned by DB layer.
        :param network_info:
           :py:meth:`~nova.network.manager.NetworkManager.get_instance_nw_info`
        :param block_device_info: Information about block devices that should
                                  be detached from the instance.
        :param destroy_disks: Indicates if disks should be destroyed
        :param migrate_data: implementation specific params
        """
        ec2_conn = self._ec2_conn(context, project_id=instance.project_id)
        ec2_id = None
        try:
            ec2_id = self._get_ec2_id_from_instance(instance)
            ec2_instances = ec2_conn.describe_instances(InstanceIds=[ec2_id])
        except ClientError as ex:
            # Exception while fetching instance info from AWS
            LOG.exception('Exception in destroy while fetching EC2 id for '
                          'instance %s. Error: %s' % instance.uuid, ex.message)
            return
        if not len(ec2_instances['Reservations']):
            # Instance already deleted on hypervisor
            LOG.warning("EC2 instance with ID %s not found" % ec2_id,
                        instance=instance)
            return
        else:
            try:
                instance = ec2_instances['Reservations'][0]['Instances'][0]
                if instance['State']['Name'] != 'terminated':
                    if instance['State']['Name'] == 'running':
                        ec2_conn.stop_instances(InstanceIds=[ec2_id],
                                                Force=True)
                    ec2_conn.terminate_instances(InstanceIds=[ec2_id])
                    self._wait_for_state(ec2_conn, instance, ec2_id,
                                         "terminated", power_state.SHUTDOWN)
            except Exception as ex:
                LOG.exception("Exception while destroying instance: %s" %
                              str(ex))
                raise ex

    def find_disk_dev(self, pre_assigned_device_names):
        # As per the documentation,
        # http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/device_naming.html
        # this function will select the first unused device name starting
        # from sdf upto sdp.
        dev_prefix = "/dev/sd"
        max_dev = 11
        for idx in range(max_dev):
            disk_dev = dev_prefix + chr(ord('f') + idx)
            if disk_dev not in pre_assigned_device_names:
                return disk_dev
        raise exception.NovaException("No free disk device names for prefix "
                                      "'%s'" % dev_prefix)

    def get_device_name_for_instance(self, instance, bdms, block_device_obj):
        ec2_id = self._get_ec2_id_from_instance(instance)
        ec2_conn = self._ec2_conn(project_id=instance.project_id)
        response = ec2_conn.describe_instances(InstanceIds=[ec2_id])
        ec2_instance = response['Reservations'][0]['Instances'][0]
        pre_assigned_device_names = []
        for bdm in ec2_instance['BlockDeviceMappings']:
            pre_assigned_device_names.append(bdm['DeviceName'])
        LOG.info("pre_assigned_device_names: %s", pre_assigned_device_names)
        block_device_name = self.find_disk_dev(pre_assigned_device_names)
        return block_device_name

    def attach_volume(self, context, connection_info, instance, mountpoint,
                      disk_bus=None, device_type=None, encryption=None):
        """Attach the disk to the instance at mountpoint using info."""
        ec2_conn = self._ec2_conn(context, project_id=instance.project_id)
        instance_name = instance['name']
        if instance_name not in self._mounts:
            self._mounts[instance_name] = {}
        self._mounts[instance_name][mountpoint] = connection_info

        volume_id = connection_info['data']['volume_id']
        ec2_id = self._get_ec2_id_from_instance(instance)

        # ec2 only attaches volumes at /dev/sdf through /dev/sdp
        ec2_conn.attach_volume(VolumeId=volume_id, InstanceId=ec2_id,
                               Device=mountpoint, DryRun=False)

    def detach_volume(self, connection_info, instance, mountpoint,
                      encryption=None):
        """Detach the disk attached to the instance."""
        try:
            del self._mounts[instance['name']][mountpoint]
        except KeyError:
            pass
        ec2_conn = self._ec2_conn(project_id=instance.project_id)
        volume_id = connection_info['data']['volume_id']
        ec2_id = self._get_ec2_id_from_instance(instance)
        ec2_conn.detach_volume(VolumeId=volume_id, InstanceId=ec2_id,
                               Device=mountpoint, Force=False, DryRun=False)

    def swap_volume(self, old_connection_info, new_connection_info,
                    instance, mountpoint, resize_to):
        """Replace the disk attached to the instance."""
        # TODO(resize_to): Use resize_to parameter
        ec2_conn = self._ec2_conn(project_id=instance.project_id)
        instance_name = instance['name']
        if instance_name not in self._mounts:
            self._mounts[instance_name] = {}
        self._mounts[instance_name][mountpoint] = new_connection_info

        new_volume_id = new_connection_info['data']['volume_id']

        self.detach_volume(old_connection_info, instance, mountpoint)
        # wait for the old volume to detach successfully to make sure
        # /dev/sdn is available for the new volume to be attached
        # TODO(remove_sleep): remove sleep and poll AWS for the status of
        # volume
        time.sleep(60)
        ec2_id = self._get_ec2_id_from_instance(instance)
        ec2_conn.attach_volume(VolumeId=new_volume_id, InstanceId=ec2_id,
                               Device=mountpoint, DryRun=False)
        return True

    def attach_interface(self, instance, image_meta, vif):
        LOG.debug("AWS: Attaching interface", instance=instance)
        if vif['id'] in self._interfaces:
            raise exception.InterfaceAttachFailed('duplicate')
        self._interfaces[vif['id']] = vif

    def detach_interface(self, instance, vif):
        LOG.debug("AWS: Detaching interface", instance=instance)
        try:
            del self._interfaces[vif['id']]
        except KeyError:
            raise exception.InterfaceDetachFailed('not attached')

    def get_info(self, instance):
        ec2_instance = vm_refs_cache.vm_ref_cache_get(instance.uuid)
        if ec2_instance is None and \
                'metadata' in instance and 'ec2_id' in instance['metadata']:
            ec2_id = instance['metadata']['ec2_id']
            ec2_conn = self._ec2_conn(project_id=instance.project_id)
            ec2_instances = ec2_conn.describe_instances(InstanceIds=[ec2_id])
            if not len(ec2_instances['Reservations']):
                LOG.warning(_("EC2 instance with ID %s not found") % ec2_id,
                            instance=instance)
                raise exception.InstanceNotFound(instance_id=instance['name'])
            ec2_instance = ec2_instances['Reservations'][0]['Instances'][0]
        if ec2_instance is None:
            # Instance was not found in cache and did not have ec2 tags
            raise exception.InstanceNotFound(instance_id=instance['name'])

        power_state = EC2_STATE_MAP.get(ec2_instance['State']['Name'])
        return hardware.InstanceInfo(state=power_state)

    def allow_key(self, key):
        for key_to_filter in DIAGNOSTIC_KEYS_TO_FILTER:
            if key == key_to_filter:
                return False
        return True

    def get_diagnostics(self, instance):
        """Return data about VM diagnostics."""
        ec2_conn = self._ec2_conn(project_id=instance.project_id)
        ec2_id = self._get_ec2_id_from_instance(instance)
        ec2_instances = ec2_conn.describe_instances(InstanceIds=[ec2_id])
        if not len(ec2_instances['Reservations']):
            LOG.warning(_("EC2 instance with ID %s not found") % ec2_id,
                        instance=instance)
            raise exception.InstanceNotFound(instance_id=instance['name'])
        ec2_instance = ec2_instances['Reservations'][0]['Instances'][0]

        diagnostics = {}
        for key, value in ec2_instance.items():
            if self.allow_key(key):
                diagnostics['instance.' + key] = str(value)

        cloudwatch_conn = self._cloudwatch_conn(project_id=instance.project_id)
        metrics = cloudwatch_conn.list_metrics(
            Dimensions=[{'InstanceId': ec2_id}])

        for metric in metrics:
            end = datetime.datetime.utcnow()
            start = end - datetime.timedelta(hours=1)
            details = metric.query(start, end, 'Average', None, 3600)
            if len(details) > 0:
                diagnostics['metrics.' + str(metric)] = details[0]
        return diagnostics

    def get_all_bw_counters(self, instances):
        """Return bandwidth usage counters for each interface on each
           running VM.
        """
        bw = []
        return bw

    def get_all_volume_usage(self, context, compute_host_bdms):
        """Return usage info for volumes attached to vms on
           a given host.
        """
        volusage = []
        return volusage

    def block_stats(self, instance_name, disk_id):
        return [0L, 0L, 0L, 0L, None]

    def interface_stats(self, instance_name, iface_id):
        return [0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L]

    def get_console_output(self, context, instance):
        ec2_conn = self._ec2_conn(context=context,
                                  project_id=instance.project_id)
        ec2_id = self._get_ec2_id_from_instance(instance)
        LOG.info("Getting console output from ec2 instance: %s", ec2_id)
        response = ec2_conn.get_console_output(InstanceId=ec2_id)
        if response['Output'] is not None:
            return response['Output']
        LOG.warning("No console logs received from AWS for instance %s",
                    ec2_id)
        return "No console logs received from AWS for instance %s" % ec2_id

    def get_vnc_console(self, context, instance):
        ec2_conn = self._ec2_conn(context, project_id=instance.project_id)
        ec2_id = self._get_ec2_id_from_instance(instance)
        LOG.info("VNC console connect to %s" % ec2_id)
        reservations = ec2_conn.describe_instances()

        vnc_port = 5901
        # Get the IP of the instance
        host_ip = None
        for reservation in reservations['Reservations']:
            for instance in reservation['Instances']:
                if instance['InstanceId'] == ec2_id:
                    if ('PublicIpAddress' in instance and
                            instance['PublicIpAddress']):
                        host_ip = instance['PublicIpAddress']
        if host_ip:
            LOG.info("Found the IP of the instance IP: %s and port: %s",
                     host_ip, vnc_port)
            return ctype.ConsoleVNC(host=host_ip, port=vnc_port)
        else:
            LOG.info("Ip not Found for the instance")
            return {'internal_access_path': 'EC2',
                    'host': 'EC2spiceconsole.com',
                    'port': 5901}

    def get_spice_console(self, instance):
        """Simple Protocol for Independent Computing Environments
        Doesn't seem to be supported by AWS EC2 directly
        """
        return {'internal_access_path': 'EC2',
                'host': 'EC2spiceconsole.com',
                'port': 6969,
                'tlsPort': 6970}

    def get_console_pool_info(self, console_type):
        return {'address': '127.0.0.1',
                'username': 'EC2user',
                'password': 'EC2password'}

    def refresh_provider_fw_rules(self):
        pass

    def get_available_resource(self, nodename):
        """Retrieve resource information.
        Updates compute manager resource info on ComputeNode table.
        This method is called when nova-compute launches and as part of a
        periodic task that records results in the DB.
        Since we don't have a real hypervisor, pretend we have lots of disk and
        ram.

        :param nodename:
            node which the caller want to get resources from
            a driver that manages only one node can safely ignore this
        :returns: Dictionary describing resources
        """
        global _EC2_NODES
        if nodename not in _EC2_NODES:
            return {}

        dic = {'vcpus': CONF.AWS.max_vcpus,
               'memory_mb': CONF.AWS.max_memory_mb,
               'local_gb': CONF.AWS.max_disk_gb,
               'vcpus_used': 0,
               'memory_mb_used': 0,
               'local_gb_used': 0,
               'hypervisor_type': 'EC2',
               'hypervisor_version': '1',
               'hypervisor_hostname': nodename,
               'disk_available_least': 0,
               'cpu_info': '?',
               'numa_topology': None}

        supported_tuple = ('IA64', 'kvm', 'hvm')
        dic["supported_instances"] = [supported_tuple]
        return dic

    def ensure_filtering_rules_for_instance(self, instance_ref, network_info):
        return

    def get_instance_disk_info(self, instance_name):
        return

    def live_migration(self, context, instance_ref, dest,
                       post_method, recover_method, block_migration=False,
                       migrate_data=None):
        post_method(context, instance_ref, dest, block_migration,
                    migrate_data)
        return

    def check_can_live_migrate_destination_cleanup(self, ctxt,
                                                   dest_check_data):
        return

    def check_can_live_migrate_destination(self, ctxt, instance_ref,
                                           src_compute_info, dst_compute_info,
                                           block_migration=False,
                                           disk_over_commit=False):
        return {}

    def check_can_live_migrate_source(self, ctxt, instance_ref,
                                      dest_check_data):
        return

    def finish_migration(self, context, migration, instance, disk_info,
                         network_info, image_meta, resize_instance,
                         block_device_info=None, power_on=True):
        """Completes a resize

        :param migration: the migrate/resize information
        :param instance: nova.objects.instance.Instance being migrated/resized
        :param power_on: is True  the instance should be powered on
        """
        ec2_conn = self._ec2_conn(context=context,
                                  project_id=instance.project_id)
        ec2_id = self._get_ec2_id_from_instance(instance)
        ec_instance_info = ec2_conn.describe_instances(InstanceIds=[ec2_id])
        ec2_instance = ec_instance_info['Reservations'][0]['Instances'][0]

        # EC2 instance needs to be stopped to modify it's attribute. So we stop
        # the instance, modify the instance type in this case, and then restart
        # the instance.
        ec2_conn.stop_instances(InstanceIds=[ec2_id])
        self._wait_for_state(ec2_conn, instance, ec2_id, "stopped",
                             power_state.SHUTDOWN)
        # TODO(flavor_map is undefined): need to check flavor type variable
        new_instance_type = flavor_map[migration['new_instance_type_id']]  # noqa
        ec2_instance.modify_attribute(
            Attribute='instanceType',
            InstanceType={'Value': new_instance_type})

    def confirm_migration(self, migration, instance, network_info):
        """Confirms a resize, destroying the source VM.

        :param instance: nova.objects.instance.Instance
        """
        ec2_conn = self._ec2_conn(project_id=instance.project_id)
        ec2_id = self._get_ec2_id_from_instance(instance)
        ec2_conn.start_instances(InstanceIds=[ec2_id])
        self._wait_for_state(ec2_conn, instance, ec2_id, "running",
                             power_state.RUNNING)

    def pre_live_migration(self, context, instance_ref, block_device_info,
                           network_info, disk, migrate_data=None):
        return

    def unfilter_instance(self, instance_ref, network_info):
        return

    def get_host_stats(self, refresh=False):
        """Return EC2 Host Status of name, ram, disk, network."""
        stats = []
        global _EC2_NODES
        for nodename in _EC2_NODES:
            host_status = self.host_status_base.copy()
            host_status['hypervisor_hostname'] = nodename
            host_status['host_hostname'] = nodename
            host_status['host_name_label'] = nodename
            host_status['hypervisor_type'] = 'Amazon-EC2'
            host_status['vcpus'] = CONF.AWS.max_vcpus
            host_status['memory_mb'] = CONF.AWS.max_memory_mb
            host_status['local_gb'] = CONF.AWS.max_disk_gb
            stats.append(host_status)
        if len(stats) == 0:
            raise exception.NovaException("EC2Driver has no node")
        elif len(stats) == 1:
            return stats[0]
        else:
            return stats

    def host_power_action(self, host, action):
        """Reboots, shuts down or powers up the host."""
        return action

    def host_maintenance_mode(self, host, mode):
        """Start/Stop host maintenance window. On start, it triggers
        guest VMs evacuation.
        """
        if not mode:
            return 'off_maintenance'
        return 'on_maintenance'

    def set_host_enabled(self, host, enabled):
        """Sets the specified host's ability to accept new instances."""
        if enabled:
            return 'enabled'
        return 'disabled'

    def get_disk_available_least(self):
        pass

    def add_to_aggregate(self, context, aggregate, host, **kwargs):
        pass

    def remove_from_aggregate(self, context, aggregate, host, **kwargs):
        pass

    def get_volume_connector(self, instance):
        return {'ip': '127.0.0.1', 'initiator': 'EC2', 'host': 'EC2host'}

    def get_available_nodes(self, refresh=False):
        global _EC2_NODES
        return _EC2_NODES

    def instance_on_disk(self, instance):
        return False

    def _get_uuid_from_aws_id(self, instance_id):
        m = hashlib.md5()
        m.update(instance_id)
        return str(uuid.UUID(bytes=m.digest(), version=4))

    def list_instance_uuids(self, node=None, template_uuids=None, force=False):
        # Refresh the local list of instances
        self.list_instances()
        return self._local_instance_uuids

    def _wait_for_state(self, ec2_conn, instance, ec2_id, desired_state,
                        desired_power_state, check_exists=False):
        """Wait for the state of the corrosponding ec2 instance to be in
        completely available state.

        :params:ec2_id: the instance's corrosponding ec2 id.
        :params:desired_state: the desired state of the instance to be in.
        """
        def _wait_for_power_state():
            """Called at an interval until the VM is running again.
            """
            try:
                response = ec2_conn.describe_instances(InstanceIds=[ec2_id])
                ec2_instance = response['Reservations'][0]['Instances'][0]
                state = ec2_instance['State']['Name']
            except ClientError as e:
                if check_exists:
                    LOG.error("Error getting instance %s. Retrying", e.message)
                    return
                raise
            if state == desired_state:
                LOG.info("Instance has changed state to %s." % desired_state)
                raise loopingcall.LoopingCallDone()

        # waiting for the power state to change
        timer = loopingcall.FixedIntervalLoopingCall(_wait_for_power_state)
        timer.start(interval=1).wait()

    def _wait_for_image_state(self, ec2_conn, ami_id, desired_state):
        """Timer to wait for the image/snapshot to reach a desired state

        :params:ami_id: correspoding image id in Amazon
        :params:desired_state: the desired new state of the image to be in.
        """
        def _wait_for_state():
            """Called at an interval until the AMI image is available."""
            try:
                images = ec2_conn.describe_images(ImageIds=[ami_id])
                state = images['Images'][0]['State']
                if state == desired_state:
                    LOG.info("Image has changed state to %s." % desired_state)
                    raise loopingcall.LoopingCallDone()
            except ClientError:
                pass

        timer = loopingcall.FixedIntervalLoopingCall(_wait_for_state)
        timer.start(interval=0.5).wait()

    def change_instance_metadata(self, context, instance, diff):
        """
        :param diff: dictionary of the format -
        {
            "key1": ["+", "value1"] # add key1=value1
            "key2": ["-"] # remove tag with key2
        }
        """
        ec2_conn = self._ec2_conn(context, project_id=instance.project_id)
        ec2_instance = vm_refs_cache.vm_ref_cache_get(instance.uuid)
        if not ec2_instance:
            ec2_id = self._get_ec2_id_from_instance(instance)
            ec2_instances = ec2_conn.describe_instances(InstanceIds=[ec2_id])
            if ec2_instances['Reservations']:
                ec2_instance = ec2_instances['Reservations'][0]['Instances'][0]
            else:
                LOG.debug('Fetched incorrect EC2 ID - %s', ec2_id)
                LOG.warn('Could not get EC2 instances for %s', instance.uuid)
                return
        ec2_id = ec2_instance['InstanceId']
        current_tags = ec2_instance.get('Tags', [])
        # Process the diff
        tags_to_add = []
        tags_to_remove = []
        for key, change in diff.items():
            op = change[0]
            if op == '+':
                if not current_tags:
                    tags_to_add.append({'Key': key, 'Value': change[1]})
                for tag in current_tags:
                    if tag['Key'] == key and tag['Value'] == change[1] or \
                            key.startswith('aws:'):
                        # Tag already present on EC2 instance
                        # OR
                        # Tag starts with "aws:" which is not allowed in AWS
                        LOG.warn('%s tag will not be added on %s instance',
                                 key, instance.uuid)
                        continue
                    else:
                        tags_to_add.append({'Key': key, 'Value': change[1]})
            if op == '-':
                for tag in current_tags:
                    if key in self._driver_tags:
                        # One of REQUIRED tags is being removed
                        LOG.warn('Trying to delete required tag on EC2. '
                                 'Tag - %s on instance %s', key, instance.uuid)
                        continue
                    if tag['Key'] == key:
                        tags_to_remove.append({'Key': key,
                                               'Value': tag['Value']})
        # Propagate the tags to EC2 instance
        if tags_to_add:
            LOG.debug('Adding %s tags to %s instance', tags_to_add,
                      instance.uuid)
            ec2_conn.create_tags(Resources=[ec2_id], Tags=tags_to_add)
        if tags_to_remove:
            LOG.debug('Removing %s tags from %s instance', tags_to_remove,
                      instance.uuid)
            ec2_conn.delete_tags(Resources=[ec2_id], Tags=tags_to_remove)
        # Update vm_refs_cache with latest tags
        ec2_instances = ec2_conn.describe_instances(InstanceIds=[ec2_id])
        if ec2_instances['Reservations']:
            ec2_instance = ec2_instances['Reservations'][0]['Instances'][0]
            vm_refs_cache.vm_ref_cache_update(instance.uuid, ec2_instance)
            LOG.debug("Updated vm_refs_cache with latest tags")
        LOG.info('Metadata change for instance %s processed', instance.uuid)

    # PF9 : Start
    def get_instance_info(self, instance_uuid):
        retval = {}
        try:
            ec2_instance = vm_refs_cache.vm_ref_cache_get(instance_uuid)
            retval['name'] = self._get_details_from_tags(ec2_instance, 'Name')
            if ec2_instance['State']['Name'] == 'terminated':
                return {}
            retval['power_state'] = EC2_STATE_MAP.get(
                ec2_instance['State']['Name'], power_state.NOSTATE)
            retval['instance_uuid'] = instance_uuid
            instance_type = ec2_instance['InstanceType']
            if instance_type not in self.ec2_flavor_info:
                instance_type = 'pf9.unknown'
            ec2_instance_type = self.ec2_flavor_info.get(instance_type)
            retval['vcpus'] = ec2_instance_type['vcpus']
            retval['memory_mb'] = ec2_instance_type['memory_mb']
            project_id = self._get_details_from_tags(ec2_instance,
                                                     'project_id')
            if project_id:
                retval['pf9_project_id'] = project_id
            bdm = []
            boot_index = 0
            volume_ids = [
                _bdm['Ebs']['VolumeId']
                for _bdm in ec2_instance['BlockDeviceMappings']
            ]
            for vol_id in volume_ids:
                if vol_id not in self._inst_vol_cache:
                    continue
                volume = self._inst_vol_cache[vol_id]
                disk_info = {}
                disk_info['device_name'] = ''
                disk_info['boot_index'] = boot_index
                disk_info['guest_format'] = 'volume'
                disk_info['source_type'] = 'blank'
                disk_info['virtual_size'] = volume['Size']
                disk_info['destination_type'] = 'local'
                disk_info['snapshot_id'] = None
                disk_info['volume_id'] = None
                disk_info['image_id'] = None
                disk_info['volume_size'] = None
                bdm.append(disk_info)
                boot_index += 1
            retval['block_device_mapping_v2'] = bdm
            return retval
        except Exception:
            LOG.exception('Could not fetch info for %s' % instance_uuid)
            return {}

    def _update_stats_pf9(self, resource_type):
        """Retrieve physical resource utilization
        """
        if resource_type not in self._pf9_stats:
            self._pf9_stats[resource_type] = {}
        data = 0
        self._pf9_stats[resource_type] = data
        return {resource_type: data}

    def _get_host_stats_pf9(self, res_types, refresh=False):
        """Return the current physical resource consumption
        """
        if refresh or not self._pf9_stats:
            self._update_stats_pf9(res_types)
        return self._pf9_stats

    def get_host_stats_pf9(self, res_types, refresh=False, nodename=None):
        """Return currently known physical resource consumption
        If 'refresh' is True, run update the stats first.
        :param res_types: An array of resources to be queried
        """
        resource_stats = dict()
        for resource_type in res_types:
            LOG.info("Looking for resource: %s" % resource_type)
            resource_dict = self._get_host_stats_pf9(resource_type,
                                                     refresh=refresh)
            resource_stats.update(resource_dict)
        return resource_stats

    def get_all_networks_pf9(self, node):
        pass

    def get_all_ip_mapping_pf9(self, needed_uuids=None):
        return {}
    # PF9 : End
