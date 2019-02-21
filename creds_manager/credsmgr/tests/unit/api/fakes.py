# Copyright 2010 OpenStack Foundation
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
from oslo_service import wsgi
import webob
import webob.dec
import webob.request


from credsmgr.api.controllers import api_version_request as api_version
from credsmgr import context


FAKE_PROJECT_ID = '9a06b8ce-4803-4b4c-89a5-27b75c1cba4b'
FAKE_USER_ID = '9a2d073f-5fd4-41ec-98b8-ee775a8f6a04'


class FakeRequestContext(context.RequestContext):
    def __init__(self, *args, **kwargs):
        kwargs['auth_token'] = kwargs.get(FAKE_USER_ID, FAKE_PROJECT_ID)
        super(FakeRequestContext, self).__init__(*args, **kwargs)


class HTTPRequest(webob.Request):

    @classmethod
    def blank(cls, *args, **kwargs):
        if args is not None:
            if 'v1' in args[0]:
                kwargs['base_url'] = 'http://localhost/v1'
            if 'v2' in args[0]:
                kwargs['base_url'] = 'http://localhost/v2'
            if 'v3' in args[0]:
                kwargs['base_url'] = 'http://localhost/v3'
        use_admin_context = kwargs.pop('use_admin_context', False)
        project_name = kwargs.pop('project_name', 'service')
        version = kwargs.pop('version', api_version._MIN_API_VERSION)
        out = wsgi.Request.blank(*args, **kwargs)
        out.environ['credsmgr.context'] = FakeRequestContext(
            FAKE_USER_ID,
            FAKE_PROJECT_ID,
            is_admin=use_admin_context,
            project_name=project_name)
        out.api_version_request = api_version.APIVersionRequest(version)
        return out
