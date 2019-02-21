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

import six

from credsmgrclient.common import exceptions
from credsmgrclient.common import http
from credsmgrclient.v1 import credentials


class Client(object):
    """Client for the OpenStack Credential Manager v1 API.
    :param string endpoint: A user-supplied endpoint URL for the glance
                            service.
    :param string token: Token for authentication.
    :param integer timeout: Allows customization of the timeout for client
                            http requests. (optional)
    """

    def __init__(self, endpoint, **kwargs):
        """Initialize a new client for the Images v1 API."""
        if not isinstance(endpoint, six.string_types):
            raise exceptions.InvalidEndpoint("Endpoint must be a string")
        base_url = endpoint + "/v1/credentials"
        self.http_client = http.get_http_client(base_url, **kwargs)
        self.credentials = credentials.CredentialManager(self.http_client)
