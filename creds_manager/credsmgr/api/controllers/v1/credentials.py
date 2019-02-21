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
import copy
import webob

from oslo_log import log as logging
from oslo_utils import uuidutils

from credsmgr.api.controllers.v1 import microversion
from credsmgr.api.controllers import wsgi
from credsmgr.db import api as db_api
from credsmgr import exception
from credsmgrclient.encrypt import ENCRYPTOR

LOG = logging.getLogger(__name__)


def _check_body(body):
    if not body:
        raise webob.exc.HTTPBadRequest(explanation="No data found in request")


def _check_admin(context):
    if not context.is_admin:
        msg = "User does not have admin privileges"
        raise webob.exc.HTTPBadRequest(explanation=msg)


def _check_uuid(uuid):
    if not uuidutils.is_uuid_like(uuid):
        msg = "Id {} is invalid".format(uuid)
        raise webob.exc.HTTPBadRequest(explanation=msg)


def _check_values(body, values):
    for value in values:
        if value not in body:
            msg = "Invalid request {} value not present".format(value)
            raise webob.exc.HTTPBadRequest(explanation=msg)


def _check_credential_exists(context, cred_id):
    credentials = db_api.credentials_get_by_id(context, cred_id).count()
    if not credentials:
        e = exception.CredentialNotFound(cred_id=cred_id)
        raise webob.exc.HTTPNotFound(explanation=e.format_message())


class CredentialController(wsgi.Controller):
    def __init__(self, provider, supported_values, encrypted_values):
        self.provider = provider
        self.supported_values = supported_values
        self.encrypted_values = encrypted_values
        super(CredentialController, self).__init__()

    @wsgi.response(201)
    def create(self, req, body):
        LOG.debug('Create %s credentials body %s', self.provider, body)
        context = req.environ['credsmgr.context']
        _check_body(body)
        _check_values(body, self.supported_values)
        properties = dict()
        for value in self.supported_values:
            if value in self.encrypted_values:
                properties[value] = ENCRYPTOR.encrypt(body[value])
            else:
                properties[value] = body[value]
        try:
            self._check_for_duplicate_entries(context, body)
        except exception.CredentialExists as e:
            raise webob.exc.HTTPConflict(explanation=e.format_message())
        cred_id = db_api.credentials_create(context, **properties)
        return dict(cred_id=cred_id)

    def _check_for_duplicate_entries(self, context, body):
        all_credentials = db_api.credential_get_all(context)
        creds_info = {}
        for credentials in all_credentials:
            if credentials.id not in creds_info:
                creds_info[credentials.id] = {}
            if credentials.name in self.encrypted_values:
                value = ENCRYPTOR.decrypt(credentials.value)
            else:
                value = credentials.value
            creds_info[credentials.id][credentials.name] = value
        for creds in creds_info.values():
            if body == creds:
                raise exception.CredentialExists()

    def update(self, req, cred_id, body):
        context = req.environ['credsmgr.context']
        _check_body(body)
        _check_uuid(cred_id)
        _check_credential_exists(context, cred_id)
        credentials = db_api.credentials_get_by_id(context, cred_id)
        _body = copy.deepcopy(body)
        for credential in credentials:
            name = credential.name
            _value = str(credential.value)
            if name in _body and _body[name] != _value:
                value = _body.pop(name)
                if name in self.encrypted_values:
                    value = ENCRYPTOR.encrypt(value)
                db_api.credential_update(context, cred_id, name, value)

    @wsgi.response(204)
    def delete(self, req, cred_id):
        context = req.environ['credsmgr.context']
        _check_uuid(cred_id)
        _check_credential_exists(context, cred_id)
        try:
            db_api.credentials_delete_by_id(context, cred_id)
        except Exception as e:
            LOG.exception("Error occurred while deleting credentials: %s" % e)
            msg = "Delete failed for credential {}".format(cred_id)
            raise webob.exc.HTTPBadRequest(explanation=msg)

    def show(self, req, body=None):
        context = req.environ['credsmgr.context']
        mversion = microversion.get_and_validate_microversion(req)
        tenant_id = req.params.get('tenant_id')
        if not tenant_id:
            _check_body(body)
            _check_values(body, ('tenant_id', ))
            tenant_id = body['tenant_id']
        _check_uuid(tenant_id)
        try:
            rows = db_api.credential_association_get_credentials(context,
                                                                 tenant_id)
        except exception.CredentialAssociationNotFound as e:
            raise webob.exc.HTTPNotFound(explanation=e.format_message())
        credential_info = {}
        for row in rows:
            credential_info[row.name] = row.value
        if mversion >= microversion.add_cred_id:
            credential_info['id'] = row.id

        if not credential_info:
            e = exception.CredentialAssociationNotFound(tenant_id=tenant_id)
            raise webob.exc.HTTPNotFound(explanation=e.format_message())

        return credential_info

    def list(self, req):
        context = req.environ['credsmgr.context']
        _check_admin(context)
        mversion = microversion.get_and_validate_microversion(req)
        populate_id = mversion >= microversion.add_cred_id
        return db_api.credential_association_get_all_credentials(
            context, populate_id=populate_id)

    @wsgi.response(201)
    def association_create(self, req, cred_id, body):
        context = req.environ['credsmgr.context']
        _check_body(body)
        _check_uuid(cred_id)
        _check_values(body, ('tenant_id', ))
        tenant_id = body['tenant_id']
        _check_uuid(tenant_id)
        # TODO(ssudake21): Verify tenant_id exists in keystone
        try:
            db_api.credential_association_create(context, cred_id, tenant_id)
        except exception.CredentialAssociationExists as e:
            raise webob.exc.HTTPConflict(explanation=e.format_message())

    @wsgi.response(204)
    def association_delete(self, req, cred_id, tenant_id):
        context = req.environ['credsmgr.context']
        _check_uuid(cred_id)
        _check_uuid(tenant_id)
        try:
            db_api.credential_association_delete(context, cred_id, tenant_id)
        except exception.CredentialAssociationNotFound as e:
            raise webob.exc.HTTPNotFound(explanation=e.format_message())

    def association_list(self, req):
        context = req.environ['credsmgr.context']
        _check_admin(context)
        credential_info = db_api.credential_association_list(context)
        return credential_info


def create_resource(provider, supported_properties, encrypted_properties):
    return wsgi.Resource(
        CredentialController(provider, supported_properties,
                             encrypted_properties))
