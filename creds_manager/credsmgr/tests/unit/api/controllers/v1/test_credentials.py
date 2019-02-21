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

from credsmgr.api.controllers.v1 import credentials
from credsmgr.db import api as db_api
from credsmgrclient.common import constants

from credsmgr.tests.unit.api import api_base
from credsmgr.tests.unit.api import fakes

import webob

LOG = logging.getLogger(__name__)


def fake_creds():
    return dict(aws_access_key_id='fake_access_key',
                aws_secret_access_key='fake_secret_key')


class CredentialControllerTest(api_base.ApiBaseTest):
    def setUp(self):
        super(CredentialControllerTest, self).setUp()
        provider_values = constants.provider_values[constants.AWS]
        self.controller = credentials.CredentialController(
            constants.AWS, provider_values['supported_values'],
            provider_values['encrypted_values'])

    def get_credentials(self, cred_id):
        context = fakes.HTTPRequest.blank('v1/credentials').environ[
            'credsmgr.context']
        credentials = db_api.credentials_get_by_id(context, cred_id)
        creds_info = {}
        for credential in credentials:
            creds_info[credential.name] = credential.value
        return creds_info

    def _call_request(self, action, *args, **kwargs):
        use_admin_context = kwargs.pop('use_admin_context', False)
        project_name = kwargs.pop('project_name', 'service')
        microversion = kwargs.pop('microversion', None)
        req = fakes.HTTPRequest.blank('v1/credentials',
                                      use_admin_context=use_admin_context,
                                      project_name=project_name)
        if microversion:
            req.headers['OpenStack-API-Version'] = microversion
        action = getattr(self.controller, action)
        return action(req, *args, **kwargs)

    def test_credentials_create(self):
        creds = fake_creds()
        resp = self._call_request('create', creds)
        self.assertTrue('cred_id' in resp)
        creds_info = self.get_credentials(resp['cred_id'])
        self.assertEqual(creds, creds_info)

    def test_credentials_create_duplicate(self):
        creds = fake_creds()
        resp = self._call_request('create', creds)
        self.assertTrue('cred_id' in resp)
        self.assertRaises(webob.exc.HTTPConflict, self._call_request,
                          'create', creds)

    def test_credentials_create_with_duplicate_values_after_deleting(self):
        creds = fake_creds()
        resp = self._call_request('create', creds)
        self.assertTrue('cred_id' in resp)
        self._call_request('delete', resp['cred_id'])
        resp = self._call_request('create', creds)
        self.assertTrue('cred_id' in resp)

    def test_credentials_update(self):
        creds = fake_creds()
        resp = self._call_request('create', creds)
        creds['aws_access_key_id'] = 'fake_access_key2'
        creds['aws_secret_access_key'] = 'fake_secret_key2'
        self._call_request('update', resp['cred_id'], creds)
        creds_info = self.get_credentials(resp['cred_id'])
        self.assertEqual(creds, creds_info)

    def test_credentials_delete(self):
        creds = fake_creds()
        resp = self._call_request('create', creds)
        self.assertTrue('cred_id' in resp)
        self._call_request('delete', resp['cred_id'])
        creds_info = self.get_credentials(resp['cred_id'])
        self.assertFalse(creds_info)

    def test_credentials_association_create(self):
        creds = fake_creds()
        resp = self._call_request('create', creds)
        self.assertTrue('cred_id' in resp)
        body = {'tenant_id': 'd37da4ea-8249-4bb7-94a2-d6a12f1b1a5c'}
        self._call_request('association_create', resp['cred_id'], body)
        creds_info = self._call_request('show', body)
        self.assertEqual(creds, creds_info)

    def test_credential_get_with_microversion(self):
        creds = fake_creds()
        resp = self._call_request('create', creds)
        self.assertTrue('cred_id' in resp)
        body = {'tenant_id': 'd37da4ea-8249-4bb7-94a2-d6a12f1b1a5c'}
        self._call_request('association_create', resp['cred_id'], body)
        creds_info = self._call_request('show', body, microversion="1.1")
        creds_id = creds_info.pop('id')
        self.assertEqual(creds_id, resp['cred_id'])
        self.assertEqual(creds, creds_info)

    def test_credential_get_with_wrong_microversion(self):
        creds = fake_creds()
        resp = self._call_request('create', creds)
        self.assertTrue('cred_id' in resp)
        body = {'tenant_id': 'd37da4ea-8249-4bb7-94a2-d6a12f1b1a5c'}
        self._call_request('association_create', resp['cred_id'], body)
        creds_info = self._call_request('show', body, microversion="a.b")
        creds_id = creds_info.pop('id', None)
        self.assertIsNone(creds_id)
        self.assertEqual(creds, creds_info)

    def test_credentials_association_delete(self):
        creds = fake_creds()
        resp = self._call_request('create', creds)
        self.assertTrue('cred_id' in resp)
        body = {'tenant_id': 'd37da4ea-8249-4bb7-94a2-d6a12f1b1a5c'}
        self._call_request('association_create', resp['cred_id'], body)
        creds_info = self._call_request('show', body)
        self.assertEqual(creds, creds_info)
        self._call_request('association_delete', resp['cred_id'],
                           body['tenant_id'])
        self.assertRaises(webob.exc.HTTPNotFound, self._call_request, 'show',
                          body)

    def test_credentials_list_without_admin(self):
        self.assertRaises(webob.exc.HTTPBadRequest, self._call_request, 'list')

    def test_credentials_list(self):
        creds = fake_creds()
        resp = self._call_request('create', creds)
        self.assertTrue('cred_id' in resp)
        project_id1 = 'd37da4ea-8249-4bb7-94a2-d6a12f1b1a5c'
        body = {'tenant_id': project_id1}
        self._call_request('association_create', resp['cred_id'], body)
        project_id2 = 'd37da4ea-8249-4bb7-94a2-d6a12f1b1a5d'
        body = {'tenant_id': project_id2}
        self._call_request('association_create', resp['cred_id'], body)
        all_creds = self._call_request('list', use_admin_context=True,
                                       project_name='services')
        self.assertEqual(len(all_creds), 2)
        self.assertIn(project_id1, all_creds)
        self.assertIn(project_id2, all_creds)

    def test_credentials_list_with_microversion(self):
        creds = fake_creds()
        resp = self._call_request('create', creds)
        self.assertTrue('cred_id' in resp)
        project_id1 = 'd37da4ea-8249-4bb7-94a2-d6a12f1b1a5c'
        body = {'tenant_id': project_id1}
        self._call_request('association_create', resp['cred_id'], body)
        project_id2 = 'd37da4ea-8249-4bb7-94a2-d6a12f1b1a5d'
        body = {'tenant_id': project_id2}
        self._call_request('association_create', resp['cred_id'], body)
        all_creds = self._call_request('list', use_admin_context=True,
                                       project_name='services',
                                       microversion="1.1")
        self.assertEqual(len(all_creds), 2)
        for _, creds in all_creds.items():
            self.assertIn('id', creds)

    def test_credentials_list_with_incorrect_microversion(self):
        creds = fake_creds()
        resp = self._call_request('create', creds)
        self.assertTrue('cred_id' in resp)
        project_id1 = 'd37da4ea-8249-4bb7-94a2-d6a12f1b1a5c'
        body = {'tenant_id': project_id1}
        self._call_request('association_create', resp['cred_id'], body)
        project_id2 = 'd37da4ea-8249-4bb7-94a2-d6a12f1b1a5d'
        body = {'tenant_id': project_id2}
        self._call_request('association_create', resp['cred_id'], body)
        all_creds = self._call_request('list', use_admin_context=True,
                                       project_name='services',
                                       microversion="a.b")
        self.assertEqual(len(all_creds), 2)
        for _, creds in all_creds.items():
            self.assertNotIn('id', creds)

    def test_credential_association_list(self):
        creds = fake_creds()
        resp = self._call_request('create', creds)
        self.assertTrue('cred_id' in resp)
        project_id1 = 'd37da4ea-8249-4bb7-94a2-d6a12f1b1a5c'
        body = {'tenant_id': project_id1}
        self._call_request('association_create', resp['cred_id'], body)
        all_creds = self._call_request('association_list',
                                       use_admin_context=True)
        self.assertEqual(len(all_creds), 1)
        self.assertIn(project_id1, all_creds)

    def test_credential_association_list_with_no_associations(self):
        all_creds = self._call_request('association_list',
                                       use_admin_context=True)
        self.assertEqual(len(all_creds), 0)
        self.assertEqual(all_creds, {})
