# Copyright 2017 Platform9 Systems Inc.(http://www.platform9.com)
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo_config import cfg

gce_group = cfg.OptGroup(name='GCE',
                         title='Options to connect to Google cloud')

gce_opts = [
    cfg.StrOpt('service_key_path', help='Service key of GCE account',
               secret=True),
    cfg.StrOpt('zone', help='GCE zone'),
    cfg.StrOpt('region', help='GCE region'),
    cfg.StrOpt('project_id', help='GCE project id'),
]

cfg.CONF.register_group(gce_group)
cfg.CONF.register_opts(gce_opts, group=gce_group)

service_key_path = cfg.CONF.GCE.service_key_path
zone = cfg.CONF.GCE.zone
region = cfg.CONF.GCE.region
project_id = cfg.CONF.GCE.project_id
