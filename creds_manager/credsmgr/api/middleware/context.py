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
from oslo_config import cfg
from oslo_middleware import request_id as oslo_request_id
from oslo_serialization import jsonutils

import credsmgr.context
from credsmgr.wsgi import common

context_opts = [
    cfg.StrOpt('admin_role', default='admin',
               help='Role used to identify an authenticated user as '
                    'administrator.')]

CONF = cfg.CONF
CONF.register_opts(context_opts)
CONF = cfg.CONF


class ContextMiddleware(common.Middleware):
    def process_request(self, req):

        """Convert authentication information into a request context

        Generate a murano.context.RequestContext object from the available
        authentication headers and store on the 'context' attribute
        of the req object.

        :param req: wsgi request object that will be given the context object
        """
        # FIXME: To be uncommented after keystone auth is enabled
        roles = [r.strip() for r in req.headers.get('X-Roles').split(',')]
        kwargs = {
            'user': req.headers.get('X-User-Id'),
            'tenant': req.headers.get('X-Project-Id'),
            'project_name': req.headers.get('X-Project-Name'),
            'auth_token': req.headers.get('X-Auth-Token'),
            # 'session': req.headers.get('X-Configuration-Session'),
            'is_admin': CONF.admin_role in roles,
            'request_id': req.environ.get(oslo_request_id.ENV_REQUEST_ID),
            'roles': roles
        }
        sc_header = req.headers.get('X-Service-Catalog')
        sc_header = None
        if sc_header:
            kwargs['service_catalog'] = jsonutils.loads(sc_header)
        req.environ['credsmgr.context'] = \
            credsmgr.context.RequestContext(**kwargs)

    @classmethod
    def factory(cls, global_conf, **local_conf):
        def filter(app):
            return cls(app)
        return filter
