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
AWS = 'aws'
GCE = 'gce'
AZURE = 'azure'
VMWARE = 'vmware'

provider_values = {
    AWS: {
        'supported_values': ['aws_access_key_id', 'aws_secret_access_key'],
        'encrypted_values': ['aws_secret_access_key']
    },
    AZURE: {
        'supported_values': ['tenant_id', 'client_id', 'client_secret',
                             'subscription_id'],
        'encrypted_values': ['client_secret']
    },
    GCE: {
        'supported_values': ['b64_key'],
        'encrypted_values': ['b64_key']
    },
    VMWARE: {
        'supported_values': ['host_username', 'host_password'],
        'encrypted_values': ['host_password']
    }
}
