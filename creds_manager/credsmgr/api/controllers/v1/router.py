# Copyright 2011 OpenStack Foundation
# Copyright 2011 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
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
from oslo_log import log as logging

from credsmgr.api.controllers.v1 import credentials
from credsmgr.api import router
from credsmgrclient.common import constants

LOG = logging.getLogger(__name__)


class APIRouter(router.APIRouter):
    """Routes requests on the API to the appropriate controller and method."""

    def _setup_routes(self, mapper):
        LOG.info("Setup routes in for credentials API")

        for provider, values_info in constants.provider_values.items():
            self.resources[provider] = credentials.create_resource(
                provider, values_info['supported_values'],
                values_info['encrypted_values'])
            self._set_resource_apis(provider, mapper)

    def _set_resource_apis(self, provider, mapper):
        controller = self.resources[provider]
        url_info = [
            {
                'action': 'create',
                'r_type': 'POST',
                'suffix': ''
            },
            {
                'action': 'show',
                'r_type': 'GET',
                'suffix': ''
            },
            {
                'action': 'list',
                'r_type': 'GET',
                'suffix': '/list'
            },
            {
                'action': 'update',
                'r_type': 'PUT',
                'suffix': '/{cred_id}'
            },
            {
                'action': 'update',
                'r_type': 'PATCH',
                'suffix': '/{cred_id}'
            },
            {
                'action': 'delete',
                'r_type': 'DELETE',
                'suffix': '/{cred_id}'
            },
            {
                'action': 'association_create',
                'r_type': 'POST',
                'suffix': '/{cred_id}/association'
            },
            {
                'action': 'association_delete',
                'r_type': 'DELETE',
                'suffix': '/{cred_id}/association/{tenant_id}'
            },
            {
                'action': 'association_list',
                'r_type': 'GET',
                'suffix': '/associations'
            }
        ]
        for info in url_info:
            uri = '/{0}{1}'.format(provider, info['suffix'])
            LOG.debug("Setup URI {0} Info {1}".format(uri, info))
            mapper.connect(uri, controller=controller, action=info['action'],
                           conditions={'method': [info['r_type']]})
