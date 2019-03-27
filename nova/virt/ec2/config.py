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
from oslo_config import cfg

from nova.compute import power_state


aws_group = cfg.OptGroup(name='AWS',
                         title='Options to connect to an AWS cloud')

aws_opts = [
    cfg.StrOpt('secret_key', help='Secret key of AWS account', secret=True),
    cfg.StrOpt('access_key', help='Access key of AWS account', secret=True),
    cfg.StrOpt('region_name', help='AWS region'),
    cfg.StrOpt('az', help='AWS availability zone'),
    cfg.BoolOpt('use_credsmgr', help='Endpoint to use for getting AWS '
                                     'credentials', default=True),
    cfg.IntOpt('vnc_port',
               default=5900,
               help='VNC starting port'),
    # 500 VCPUs
    cfg.IntOpt('max_vcpus',
               default=500,
               help='Max number of vCPUs that can be used'),
    # 1000 GB RAM
    cfg.IntOpt('max_memory_mb',
               default=1024000,
               help='Max memory MB that can be used'),
    # 1 TB Storage
    cfg.IntOpt('max_disk_gb',
               default=1024,
               help='Max storage in GB that can be used'),
    cfg.BoolOpt('enable_keypair_notifications', default=True,
                help='Listen to keypair delete notifications and act on them')
]

keystone_authtoken_group = cfg.OptGroup(name='keystone_authtoken',
                                        title='Options to connect to Keystone')

keystone_authtoken_opts = [
        cfg.StrOpt('identity_uri', help='Keystone url'),
        cfg.StrOpt('username', help='Keystone Username'),
        cfg.StrOpt('password', help='Keystone Password'),
        cfg.StrOpt('project_name', help='Project name'),
        cfg.StrOpt('region_name', help='AWS region name'),
        cfg.StrOpt('admin_user', help='Keystone admin username'),
        cfg.StrOpt('admin_password', help='Keystone admin password'),
        cfg.StrOpt('admin_tenant_name', help='Keystone admin tenant name')
]

CONF = cfg.CONF

CONF.register_group(aws_group)
CONF.register_opts(aws_opts, group=aws_group)
CONF.register_group(keystone_authtoken_group)
CONF.register_opts(keystone_authtoken_opts, group=keystone_authtoken_group)


EC2_STATE_MAP = {
    "pending": power_state.NOSTATE,
    "running": power_state.RUNNING,
    "shutting-down": power_state.NOSTATE,
    "terminated": power_state.CRASHED,
    "stopping": power_state.NOSTATE,
    "stopped": power_state.SHUTDOWN
}

EC2_FLAVOR_MAP = {
    'c3.2xlarge': {'memory_mb': 15360.0, 'vcpus': 8},
    'c3.4xlarge': {'memory_mb': 30720.0, 'vcpus': 16},
    'c3.8xlarge': {'memory_mb': 61440.0, 'vcpus': 32},
    'c3.large': {'memory_mb': 3840.0, 'vcpus': 2},
    'c3.xlarge': {'memory_mb': 7680.0, 'vcpus': 4},
    'c4.2xlarge': {'memory_mb': 15360.0, 'vcpus': 8},
    'c4.4xlarge': {'memory_mb': 30720.0, 'vcpus': 16},
    'c4.8xlarge': {'memory_mb': 61440.0, 'vcpus': 36},
    'c4.large': {'memory_mb': 3840.0, 'vcpus': 2},
    'c4.xlarge': {'memory_mb': 7680.0, 'vcpus': 4},
    'd2.2xlarge': {'memory_mb': 62464.0, 'vcpus': 8},
    'd2.4xlarge': {'memory_mb': 124928.0, 'vcpus': 16},
    'd2.8xlarge': {'memory_mb': 249856.0, 'vcpus': 36},
    'd2.xlarge': {'memory_mb': 31232.0, 'vcpus': 4},
    'g2.2xlarge': {'memory_mb': 15360.0, 'vcpus': 8},
    'g2.8xlarge': {'memory_mb': 61440.0, 'vcpus': 32},
    'i2.2xlarge': {'memory_mb': 62464.0, 'vcpus': 8},
    'i2.4xlarge': {'memory_mb': 124928.0, 'vcpus': 16},
    'i2.8xlarge': {'memory_mb': 249856.0, 'vcpus': 32},
    'i2.xlarge': {'memory_mb': 31232.0, 'vcpus': 4},
    'm3.2xlarge': {'memory_mb': 30720.0, 'vcpus': 8},
    'm3.large': {'memory_mb': 7680.0, 'vcpus': 2},
    'm3.medium': {'memory_mb': 3840.0, 'vcpus': 1},
    'm3.xlarge': {'memory_mb': 15360.0, 'vcpus': 4},
    'm4.10xlarge': {'memory_mb': 163840.0, 'vcpus': 40},
    'm4.2xlarge': {'memory_mb': 32768.0, 'vcpus': 8},
    'm4.4xlarge': {'memory_mb': 65536.0, 'vcpus': 16},
    'm4.large': {'memory_mb': 8192.0, 'vcpus': 2},
    'm4.xlarge': {'memory_mb': 16384.0, 'vcpus': 4},
    'r3.2xlarge': {'memory_mb': 62464.0, 'vcpus': 8},
    'r3.4xlarge': {'memory_mb': 124928.0, 'vcpus': 16},
    'r3.8xlarge': {'memory_mb': 249856.0, 'vcpus': 32},
    'r3.large': {'memory_mb': 15616.0, 'vcpus': 2},
    'r3.xlarge': {'memory_mb': 31232.0, 'vcpus': 4},
    't2.large': {'memory_mb': 8192.0, 'vcpus': 2},
    't2.medium': {'memory_mb': 4096.0, 'vcpus': 2},
    't2.micro': {'memory_mb': 1024.0, 'vcpus': 1},
    't2.nano': {'memory_mb': 512.0, 'vcpus': 1},
    't2.small': {'memory_mb': 2048.0, 'vcpus': 1},
    'x1.32xlarge': {'memory_mb': 1998848.0, 'vcpus': 128},
    't1.micro': {'memory_mb': 613.0, 'vcpus': 1},
    'pf9.unknown': {'memory_mb': 1024.0, 'vcpus': 1}
}
