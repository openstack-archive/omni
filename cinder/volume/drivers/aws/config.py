"""
Copyright 2017 Platform9 Systems Inc.(http://www.platform9.com)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
from oslo_config import cfg

aws_group = cfg.OptGroup(name='AWS',
                         title='Options to connect to an AWS environment')
aws_opts = [
    cfg.StrOpt('secret_key', help='Secret key of AWS account', secret=True),
    cfg.StrOpt('access_key', help='Access key of AWS account', secret=True),
    cfg.StrOpt('region_name', help='AWS region'),
    cfg.StrOpt('az', help='AWS availability zone'),
    cfg.IntOpt('wait_time_min', help='Maximum wait time for AWS operations',
               default=5),
    cfg.BoolOpt('use_credsmgr', help='Should credentials manager be used',
                default=True)
]

ebs_opts = [
    cfg.StrOpt('ebs_pool_name', help='Storage pool name'),
    cfg.IntOpt('ebs_free_capacity_gb',
               help='Free space available on EBS storage pool', default=1024),
    cfg.IntOpt('ebs_total_capacity_gb',
               help='Total space available on EBS storage pool', default=1024)
]

cinder_opts = [
    cfg.StrOpt('os_region_name',
               help='Region name of this node'),
]

CONF = cfg.CONF
CONF.register_group(aws_group)
CONF.register_opts(aws_opts, group=aws_group)
CONF.register_opts(ebs_opts)
CONF.register_opts(cinder_opts)
