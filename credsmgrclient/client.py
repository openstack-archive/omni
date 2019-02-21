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

from oslo_utils import importutils


def Client(endpoint, version=1, **kwargs):
    """Client for the OpenStack Credential manager API."""
    module_string = '.'.join(('credsmgrclient', 'v%s' % int(version),
                              'client'))
    module = importutils.import_module(module_string)
    client_class = getattr(module, 'Client')
    return client_class(endpoint, **kwargs)
