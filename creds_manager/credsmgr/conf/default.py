# Copyright 2017 Platform9 Systems
# All Rights Reserved.
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
CONF = cfg.CONF

default_opts = [
    cfg.StrOpt('credsmgr_api_listen_port',
               help='Credential Manager API listen Port'),

    cfg.BoolOpt('credsmgr_api_use_ssl',
                default=False,
                help='SSL for Credential Manager API'),

    cfg.IntOpt('credsmgr_api_workers',
               default=1,
               help='Number of workers for Credential Manager API service')
]


def register_opts(conf):
    conf.register_opts(default_opts)
