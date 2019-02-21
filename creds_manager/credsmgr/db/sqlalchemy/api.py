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

import sys

from oslo_config import cfg
from oslo_db import exception as db_exception
from oslo_db import options
from oslo_db.sqlalchemy import session as db_session
from oslo_db.sqlalchemy import utils as db_utils
from oslo_log import log as logging
from oslo_utils import uuidutils
from sqlalchemy.orm import exc as orm_exception

from credsmgr.db.sqlalchemy import models
from credsmgr import exception

CONF = cfg.CONF

options.set_defaults(CONF)

LOG = logging.getLogger(__name__)

_facade = None


def get_facade():
    global _facade

    if not _facade:
        _facade = db_session.EngineFacade.from_config(CONF)

    return _facade


def get_engine():
    return get_facade().get_engine()


def get_session():
    return get_facade().get_session()


def get_backend():
    """The backend is this module itself."""
    return sys.modules[__name__]


def _get_context_values(context):
    return {
        'owner_user_id': context.user_id,
        'owner_project_id': context.project_id
    }


def credential_create(context, cred_id, name, value):
    pass


def credential_get(context, cred_id, name):
    try:
        return db_utils.model_query(
            models.Credential, context.session, deleted=False).\
            filter_by(id=cred_id, name=name).one()
    except orm_exception.NoResultFound:
        raise exception.CredentialNotFound(cred_id=cred_id)


def credential_get_all(context):
    return db_utils.model_query(models.Credential, context.session,
                                deleted=False)


def credential_update(context, cred_id, name, value):
    _credential = credential_get(context, cred_id, name)
    _credential.value = value
    _credential.save(context.session)


def credential_delete(context, cred_id, name):
    pass


def credentials_create(context, **kwargs):
    session = context.session
    cred_id = uuidutils.generate_uuid()
    context_values = _get_context_values(context)

    with session.begin():
        for k, v in kwargs.items():
            cp = models.Credential(id=cred_id, name=k, value=v)
            cp.update(context_values)
            session.add(cp)
    return cred_id


def credentials_get_by_id(context, cred_id):
    try:
        return db_utils.model_query(
            models.Credential, context.session, deleted=False).\
            filter_by(id=cred_id)
    except orm_exception.NoResultFound:
        raise exception.CredentialNotFound(cred_id=cred_id)


def credentials_delete_by_id(context, cred_id):
    query = credentials_get_by_id(context, cred_id)
    for credential in query:
        credential.soft_delete(context.session)


def credential_association_list(context):
    all_credentials = {}
    all_associations = db_utils.model_query(
        models.CredentialsAssociation, context.session, deleted=False)
    for association in all_associations:
        all_credentials[association.project_id] = association.credential_id
    return all_credentials


def credential_association_get_all_credentials(context, populate_id=False):
    def _extract_creds(credentials):
        credential_info = {}
        for credential in credentials:
            credential_info[credential.name] = credential.value
        if populate_id:
            credential_info['id'] = credential.id
        return credential_info

    all_credentials = {}
    all_associations = db_utils.model_query(
        models.CredentialsAssociation, context.session, deleted=False)
    for association in all_associations:
        creds = _extract_creds(association.credentials)
        all_credentials[association.project_id] = creds
    return all_credentials


def credential_association_get_credentials(context, project_id):
    try:
        creds_association = db_utils.model_query(
            models.CredentialsAssociation, context.session, deleted=False).\
            filter_by(project_id=project_id).one()
    except orm_exception.NoResultFound:
        raise exception.CredentialAssociationNotFound(tenant_id=project_id)
    credentials = creds_association.credentials
    return credentials


def credential_association_create(context, cred_id, project_id):
    session = context.session
    context_values = _get_context_values(context)

    try:
        with session.begin():
            creds_association = models.CredentialsAssociation(
                project_id=project_id,
                credential_id=cred_id)
            creds_association.update(context_values)
            session.add(creds_association)
    except db_exception.DBDuplicateEntry:
        raise exception.CredentialAssociationExists(tenant_id=project_id)


def credential_association_delete(context, cred_id, project_id):
    try:
        creds_association = db_utils.model_query(
            models.CredentialsAssociation, context.session, deleted=False).\
            filter_by(credential_id=cred_id).\
            filter_by(project_id=project_id).one()
    except orm_exception.NoResultFound:
        raise exception.CredentialAssociationNotFound(tenant_id=project_id)
    creds_association.soft_delete(context.session)
