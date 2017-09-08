"""
Copyright 2017 Platform9 Systems Inc.(http://www.platform9.com)
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
import nova.conf
from oslo_config import cfg

azure_group = cfg.OptGroup(
    name='azure', title='Options to connect to Azure cloud')

azure_opts = [
    cfg.StrOpt('tenant_id', help='Tenant id of Azure account'),
    cfg.StrOpt('client_id', help='Azure client id'),
    cfg.StrOpt('client_secret', help='Azure Client secret', secret=True),
    cfg.StrOpt('subscription_id', help='Azure subscription id'),
    cfg.StrOpt('region', help='Azure region'),
    cfg.StrOpt('resource_group', help="Azure resource group"),
    cfg.StrOpt(
        'vm_admin_username',
        default='azureuser',
        help=('Specifies the name of the administrator',
              'account in virtual machine')),
    cfg.IntOpt('vnc_port', default=5900, help='VNC starting port'),
    # 500 VCPUs
    cfg.IntOpt(
        'max_vcpus', default=500, help='Max number of vCPUs that can be used'),
    # 1000 GB RAM
    cfg.IntOpt(
        'max_memory_mb',
        default=1024000,
        help='Max memory MB that can be used'),
    # 1 TB Storage
    cfg.IntOpt(
        'max_disk_gb', default=1024, help='Max storage in GB that can be used')
]

CONF = nova.conf.CONF
CONF.register_group(azure_group)
CONF.register_opts(azure_opts, group=azure_group)

nova_conf = CONF
azure_conf = CONF.azure
