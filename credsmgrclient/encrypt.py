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
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import importutils

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

no_encryption = 'credsmgrclient.encryption.noop.NoEncryption'
encryptor_opts = [
    cfg.StrOpt('encryptor', help='Encryption driver',
               default=no_encryption),
]
CONF.register_opts(encryptor_opts, group='credsmgr')

try:
    ENCRYPTOR = importutils.import_object(CONF.credsmgr.encryptor)
except ImportError:
    LOG.error('Could not load encryption class: %s' % CONF.credsmgr.encryptor)
    raise
