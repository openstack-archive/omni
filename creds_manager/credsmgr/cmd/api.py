#!/usr/bin/env python
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
"""Starter script for Credsmgr API."""
import eventlet  # noqa
eventlet.monkey_patch()  # noqa

import socket
import sys

from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import service as oslo_service

# Need to register global_opts
from credsmgr import conf as credsmgr_conf  # noqa
from credsmgr import service

CONF = cfg.CONF

host_opt = cfg.StrOpt('host', default=socket.gethostname(),
                      help='Credsmgr host')

CONF.register_opts([host_opt])


def main():
    logging.register_options(CONF)
    CONF(sys.argv[1:], project='credsmgr', version=".1")
    logging.setup(CONF, "credsmgr")
    service_instance = service.WSGIService('credsmgr_api')
    service_launcher = oslo_service.ProcessLauncher(CONF)
    service_launcher.launch_service(service_instance,
                                    workers=service_instance.workers)
    service_launcher.wait()
