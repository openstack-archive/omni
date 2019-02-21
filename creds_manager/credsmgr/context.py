# Copyright 2011 OpenStack Foundation
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
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

"""RequestContext: context for requests that persist through credsmgr."""

import copy
import policy
import six

from oslo_config import cfg
from oslo_context import context
from oslo_log import log as logging
from oslo_utils import timeutils

from credsmgr.db import api as db_api

CONF = cfg.CONF

LOG = logging.getLogger(__name__)


class RequestContext(context.RequestContext):
    """Security context and request information.

    Represents the user taking a given action within the system.

    """
    def __init__(self, user_id=None, project_id=None, is_admin=None,
                 read_deleted="no", project_name=None, remote_address=None,
                 timestamp=None, quota_class=None, service_catalog=None,
                 **kwargs):
        """Initialize RequestContext.

        :param read_deleted: 'no' indicates deleted records are hidden, 'yes'
            indicates deleted records are visible, 'only' indicates that
            *only* deleted records are visible.

        :param overwrite: Set to False to ensure that the greenthread local
            copy of the index is not overwritten.
        """
        # NOTE(jamielennox): oslo.context still uses some old variables names.
        # These arguments are maintained instead of passed as kwargs to
        # maintain the interface for tests.
        kwargs.setdefault('user', user_id)
        kwargs.setdefault('tenant', project_id)

        super(RequestContext, self).__init__(is_admin=is_admin, **kwargs)

        self.project_name = project_name
        self.read_deleted = read_deleted
        self.remote_address = remote_address
        if not timestamp:
            timestamp = timeutils.utcnow()
        elif isinstance(timestamp, six.string_types):
            timestamp = timeutils.parse_isotime(timestamp)
        self.timestamp = timestamp
        self.quota_class = quota_class
        self._session = None
        if service_catalog:
            # Only include required parts of service_catalog
            self.service_catalog = [s for s in service_catalog
                                    if s.get('type') in
                                    ('identity', 'compute', 'credsmgr')]
        else:
            # if list is empty or none
            self.service_catalog = []

        # We need to have RequestContext attributes defined
        # when policy.check_is_admin invokes request logging
        # to make it loggable.
        if self.is_admin is None:
            self.is_admin = policy.check_is_admin(self.roles, self)
        elif self.is_admin and 'admin' not in self.roles:
            self.roles.append('admin')

    def _get_read_deleted(self):
        return self._read_deleted

    def _set_read_deleted(self, read_deleted):
        if read_deleted not in ('no', 'yes', 'only'):
            raise ValueError("read_deleted can only be one of 'no',"
                             "'yes' or 'only', not %r" % read_deleted)
        self._read_deleted = read_deleted

    def _del_read_deleted(self):
        del self._read_deleted

    read_deleted = property(_get_read_deleted, _set_read_deleted,
                            _del_read_deleted)

    def to_dict(self):
        result = super(RequestContext, self).to_dict()
        result['user_id'] = self.user_id
        result['project_id'] = self.project_id
        result['project_name'] = self.project_name
        result['domain'] = self.domain
        result['read_deleted'] = self.read_deleted
        result['remote_address'] = self.remote_address
        result['timestamp'] = self.timestamp.isoformat()
        result['quota_class'] = self.quota_class
        result['service_catalog'] = self.service_catalog
        result['request_id'] = self.request_id
        return result

    @classmethod
    def from_dict(cls, values):
        return cls(user_id=values.get('user_id'),
                   project_id=values.get('project_id'),
                   project_name=values.get('project_name'),
                   domain=values.get('domain'),
                   read_deleted=values.get('read_deleted'),
                   remote_address=values.get('remote_address'),
                   timestamp=values.get('timestamp'),
                   quota_class=values.get('quota_class'),
                   service_catalog=values.get('service_catalog'),
                   request_id=values.get('request_id'),
                   is_admin=values.get('is_admin'),
                   roles=values.get('roles'),
                   auth_token=values.get('auth_token'),
                   user_domain=values.get('user_domain'),
                   project_domain=values.get('project_domain'))

    def to_policy_values(self):
        policy = super(RequestContext, self).to_policy_values()

        policy['is_admin'] = self.is_admin

        return policy

    def elevated(self, read_deleted=None, overwrite=False):
        """Return a version of this context with admin flag set."""
        context = self.deepcopy()
        context.is_admin = True

        if 'admin' not in context.roles:
            context.roles.append('admin')

        if read_deleted is not None:
            context.read_deleted = read_deleted

        return context

    def deepcopy(self):
        return copy.deepcopy(self)

    # NOTE(sirp): the openstack/common version of RequestContext uses
    # tenant/user whereas the Credsmgr version uses project_id/user_id.
    # NOTE(adrienverge): The Credsmgr version of RequestContext now uses
    # tenant/user internally, so it is compatible with context-aware code from
    # openstack/common. We still need this shim for the rest of Credsmgr's
    # code.
    @property
    def project_id(self):
        return self.tenant

    @project_id.setter
    def project_id(self, value):
        self.tenant = value

    @property
    def user_id(self):
        return self.user

    @user_id.setter
    def user_id(self, value):
        self.user = value

    @property
    def session(self):
        if self._session is None:
            self._session = db_api.get_session()
        return self._session


def get_admin_context(read_deleted="no"):
    return RequestContext(user_id=None,
                          project_id=None,
                          is_admin=True,
                          read_deleted=read_deleted,
                          overwrite=False)
