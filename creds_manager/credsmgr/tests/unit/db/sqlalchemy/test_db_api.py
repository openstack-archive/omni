# Copyright 2017 Platform9 Systems, Inc.
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

from credsmgr import context
from credsmgr.db import api as db_api
from credsmgr import exception
import credsmgr.tests.unit.db.test_db as test_db

LOG = logging.getLogger(__name__)


class TestDBApi(test_db.BaseTest):
    def setUp(self):
        super(TestDBApi, self).setUp()
        self.ctxt = context.get_admin_context()
        self.ctxt.user_id = 'fake-user'
        self.ctxt.project_id = 'fake-project'

    @staticmethod
    def default_aws_credential_values():
        return dict(
            aws_access_key_id='fake_access_key',
            aws_secret_access_key='fake_secret_key', )

    def get_credentials(self, cred_id):
        credentials = db_api.credentials_get_by_id(self.ctxt, cred_id)
        creds_info = {}
        for credential in credentials:
            creds_info[credential.name] = credential.value
        return creds_info

    def _setup_credentials(self):
        values = self.default_aws_credential_values()
        cred_id = db_api.credentials_create(self.ctxt, **values)
        creds_info = self.get_credentials(cred_id)
        self.assertEqual(len(creds_info), 2)
        self.assertEqual(values, creds_info)
        return cred_id

    def test_credentials_create(self):
        self._setup_credentials()

    def test_credentials_update(self):
        cred_id = self._setup_credentials()
        values = self.default_aws_credential_values()
        values['aws_access_key_id'] = 'fake_access_key2'
        values['aws_secret_access_key'] = 'fake_secret_key2'
        for k, v in values.items():
            db_api.credential_update(self.ctxt, cred_id, k, v)
        creds_info = self.get_credentials(cred_id)
        self.assertEqual(len(creds_info), 2)
        self.assertEqual(values, creds_info)

    def test_credential_update_with_different_keys(self):
        cred_id = self._setup_credentials()
        values = {
            'x-aws_access_key_id': 'fake_access_key2',
            'x-aws_secret_access_key': 'fake_secret_key2'
        }
        for k, v in values.items():
            self.assertRaises(exception.CredentialNotFound,
                              db_api.credential_update, self.ctxt, cred_id, k,
                              v)

    def test_credentials_delete(self):
        cred_id = self._setup_credentials()
        db_api.credentials_delete_by_id(self.ctxt, cred_id)
        creds_info = self.get_credentials(cred_id)
        self.assertEqual(len(creds_info), 0)

    def test_credentials_association(self):
        cred_id = self._setup_credentials()
        project_id = 'd37da4ea-8249-4bb7-94a2-d6a12f1b1a5c'
        db_api.credential_association_create(self.ctxt, cred_id, project_id)
        credentials = db_api.credential_association_get_credentials(
            self.ctxt, project_id)
        creds_info = {}
        for credential in credentials:
            creds_info[credential.name] = credential.value
        values = self.default_aws_credential_values()
        self.assertEqual(len(creds_info), 2)
        self.assertEqual(values, creds_info)
        db_api.credential_association_delete(self.ctxt, cred_id, project_id)

    def test_credentials_association_exists(self):
        cred_id = self._setup_credentials()
        project_id = 'd37da4ea-8249-4bb7-94a2-d6a12f1b1a5c'
        db_api.credential_association_create(self.ctxt, cred_id, project_id)
        self.assertRaises(exception.CredentialAssociationExists,
                          db_api.credential_association_create, self.ctxt,
                          cred_id, project_id)
        db_api.credential_association_delete(self.ctxt, cred_id, project_id)
        db_api.credential_association_create(self.ctxt, cred_id, project_id)

    def test_credential_association_does_not_exist(self):
        project_id = 'd37da4ea-8249-4bb7-94a2-d6a12f1b1a5c'
        self.assertRaises(exception.CredentialAssociationNotFound,
                          db_api.credential_association_get_credentials,
                          self.ctxt, project_id)

    def test_credential_association_does_not_exist_after_delete(self):
        cred_id = self._setup_credentials()
        project_id = 'd37da4ea-8249-4bb7-94a2-d6a12f1b1a5c'
        db_api.credential_association_create(self.ctxt, cred_id, project_id)
        self.assertRaises(exception.CredentialAssociationExists,
                          db_api.credential_association_create, self.ctxt,
                          cred_id, project_id)
        db_api.credential_association_delete(self.ctxt, cred_id, project_id)
        self.assertRaises(exception.CredentialAssociationNotFound,
                          db_api.credential_association_get_credentials,
                          self.ctxt, project_id)

    def test_credential_association_get_all_credentials(self):
        cred_id = self._setup_credentials()
        project_id1 = 'd37da4ea-8249-4bb7-94a2-d6a12f1b1a5c'
        project_id2 = 'd37da4ea-8249-4bb7-94a2-d6a12f1b1a5d'
        db_api.credential_association_create(self.ctxt, cred_id, project_id1)
        db_api.credential_association_create(self.ctxt, cred_id, project_id2)
        all_creds = db_api.credential_association_get_all_credentials(
            self.ctxt)
        self.assertIn(project_id1, all_creds)
        self.assertIn(project_id2, all_creds)
        self.assertEqual(len(all_creds), 2)

    def test_credential_association_list(self):
        cred_id = self._setup_credentials()
        project_id1 = 'd37da4ea-8249-4bb7-94a2-d6a12f1b1a5c'
        db_api.credential_association_create(self.ctxt, cred_id, project_id1)
        all_creds = db_api.credential_association_list(self.ctxt)
        self.assertIn(project_id1, all_creds)
        self.assertEqual(len(all_creds), 1)
