# Copyright 2017 Platform9 Systems.
#
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
import sys

from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import service as oslo_service

from credsmgr import conf  # noqa
from credsmgr import service

CONF = cfg.CONF

logging.register_options(CONF)
CONF(sys.argv[1:], project='credsmgr', version=".1")
logging.setup(CONF, "credsmgr")
service_instance = service.WSGIService('credsmgr_api')
service_launcher = oslo_service.ProcessLauncher(CONF)
service_launcher.launch_service(service_instance,
                                workers=service_instance.workers)
service_launcher.wait()
