# Copyright 2018 Platform9 Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from oslo_log import log as logging

LOG = logging.getLogger(__name__)

microversion_header = 'OpenStack-API-Version'
default_microversion = 1.0
# 1.1: adds credential ID to GET /aws?tenant_id=<> and /aws/list
#      APIs.
add_cred_id = 1.1
valid_microversions = [default_microversion, add_cred_id]


def get_and_validate_microversion(request):
    """
    :param request: API request object to parse
    """
    microversion_str = request.headers.get(microversion_header,
                                           str(default_microversion))
    try:
        microversion = float(microversion_str)
    except ValueError:
        LOG.error('Incorrect microversion specified - %s', microversion_str)
        microversion = default_microversion
    if microversion not in valid_microversions:
        LOG.error('Invalid microversion specified - %s, using default'
                  ' microversion', microversion_str)
        microversion = default_microversion
    return microversion
