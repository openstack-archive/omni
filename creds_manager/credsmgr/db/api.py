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

from oslo_config import cfg
from oslo_db import api
from oslo_log import log as logging

CONF = cfg.CONF

log = logging.getLogger(__name__)


_BACKEND_MAPPING = {'sqlalchemy': 'credsmgr.db.sqlalchemy.api'}

IMPL = api.DBAPI.from_config(CONF, backend_mapping=_BACKEND_MAPPING)


def get_engine():
    return IMPL.get_engine()


def get_session():
    return IMPL.get_session()


def credential_create(context, name, value):
    return IMPL.credential_create(context, name, value)


def credential_get(context, name):
    return IMPL.credential_get(context, name)


def credential_get_all(context):
    return IMPL.credential_get_all(context)


def credential_update(context, cred_id, name, value):
    return IMPL.credential_update(context, cred_id, name, value)


def credential_delete(context, cred_id, name):
    return IMPL.credential_delete(context, cred_id, name)


def credentials_create(context, **kwargs):
    return IMPL.credentials_create(context, **kwargs)


def credentials_get_by_id(context, cred_id):
    return IMPL.credentials_get_by_id(context, cred_id)


def credentials_delete_by_id(context, cred_id):
    return IMPL.credentials_delete_by_id(context, cred_id)


def credential_association_get_all_credentials(context, populate_id=False):
    return IMPL.credential_association_get_all_credentials(
        context, populate_id=populate_id)


def credential_association_list(context):
    return IMPL.credential_association_list(context)


def credential_association_get_credentials(context, project_id):
    return IMPL.credential_association_get_credentials(context, project_id)


def credential_association_create(context, cred_id, project_id):
    return IMPL.credential_association_create(context, cred_id, project_id)


def credential_association_delete(context, cred_id, project_id):
    return IMPL.credential_association_delete(context, cred_id, project_id)
