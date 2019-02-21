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
import base64
import six

from credsmgrclient.encryption import base
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from oslo_config import cfg
from oslo_log import log as logging

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

encrypt_opts = [
    cfg.StrOpt('fernet_salt', help='Salt to be used for generating fernet key.'
                                   'Should be 16 bytes', required=True),
    cfg.StrOpt('fernet_password', help='Password to be used for generating'
                                       'fernet key', required=True),
    cfg.IntOpt('iterations', help='Number of iterations for generating key'
                                  'from password and salt',
               default=100000)
]
CONF.register_opts(encrypt_opts, group='credsmgr')


class FernetKeyEncryption(base.Encryptor):

    def __init__(self):
        fernet_password = CONF.credsmgr.fernet_password
        fernet_salt = CONF.credsmgr.fernet_salt
        iterations = CONF.credsmgr.iterations
        kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=32,
                         salt=fernet_salt, iterations=iterations,
                         backend=default_backend())
        key = base64.urlsafe_b64encode(kdf.derive(fernet_password))
        self.fernet_key = Fernet(key)

    def encrypt(self, data):
        if isinstance(data, six.types.UnicodeType):
            data = data.encode('utf-8')
        return self.fernet_key.encrypt(data)

    def decrypt(self, data):
        if isinstance(data, six.types.UnicodeType):
            data = data.encode('utf-8')
        try:
            return self.fernet_key.decrypt(data)
        except InvalidToken:
            return data
