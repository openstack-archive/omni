"""
Copyright 2017 Platform9 Systems Inc.(http://www.platform9.com)
Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""

import logging

from credsmgrclient.common.constants import provider_values
from credsmgrclient.encrypt import ENCRYPTOR

LOG = logging.getLogger(__name__)


def _get_encrypted_values(provider):
    try:
        return provider_values[provider]['encrypted_values']
    except KeyError:
        raise Exception("Provider %s is not valid" % provider)


def _decrypt_creds(creds, encrypted_values):
    for k, v in creds.items():
        if k in encrypted_values:
            creds[k] = ENCRYPTOR.decrypt(v)


class CredentialManager(object):

    def __init__(self, http_client):
        self.client = http_client

    def credentials_get(self, provider, tenant_id):
        """Get the information about Credentials.
        :param provider: Name of Omni provider
        :type: str
        :param tenant_id: tenant id to look up
        :type: str
        :rtype: dict
        """
        resp, body = self.client.get("/%s" % provider,
                                     data={"tenant_id": tenant_id})
        LOG.debug("Get Credentials response: {0}, body: {1}".format(
            resp, body))
        if body:
            encrypted_values = _get_encrypted_values(provider)
            _decrypt_creds(body, encrypted_values)
        return resp, body

    def credentials_list(self, provider):
        """Get the information about Credentials for all tenants.
        :param provider: Name of Omni provider
        :type: str
        :rtype: dict
        """
        resp, body = self.client.get("/%s/list" % provider)
        LOG.debug("Get Credentials list response: {0}, body: {1}".format(
            resp, body))
        if body:
            encrypted_values = _get_encrypted_values(provider)
            for creds in body.values():
                _decrypt_creds(creds, encrypted_values)
        return resp, body

    def credentials_create(self, provider, **kwargs):
        """Create a credential.
        :param provider: Name of Omni provider
        :type: str
        :param body: Credentials for Omni provider
        :type: dict
        :rtype: dict
        """
        resp, body = self.client.post("/%s" % provider,
                                      data=kwargs.get('body'))
        LOG.debug("Post Credentials response: {0}, body: {1}".format(resp,
                                                                     body))
        return resp, body

    def credentials_delete(self, provider, credential_id):
        """Delete a credential.
        :param provider: Name of Omni provider
        :type: str
        :param credential_id: ID for credential
        :type: str
        """
        resp, body = self.client.delete("/%s/%s" % (provider, credential_id))
        LOG.debug("Delete Credentials response: {0}, body: {1}".format(
            resp, body))

    def credentials_update(self, provider, credential_id, **kwargs):
        """Update credential.
        :param provider: Name of Omni provider
        :type: str
        :param credential_id: ID for credential
        :type: str
        """
        resp, body = self.client.put("/%s/%s" % (provider, credential_id),
                                     data=kwargs.get('body'))
        LOG.debug("Update Credentials response: {0}, body: {1}".format(
            resp, body))
        return resp, body

    def credentials_association_create(self, provider, credential_id,
                                       **kwargs):
        resp, body = self.client.post(
            "/%s/%s/association" % (provider, credential_id),
            data=kwargs.get('body'))
        LOG.debug("Create Association response: {0}, body: {1}".format(
            resp, body))

    def credentials_association_delete(self, provider, credential_id,
                                       tenant_id):
        resp, body = self.client.delete(
            "/%s/%s/association/%s" % (provider, credential_id, tenant_id))
        LOG.debug("Delete Association response: {0}, body: {1}".format(
            resp, body))

    def credentials_association_list(self, provider):
        resp, body = self.client.get("/%s/associations" % provider)
        LOG.debug("List associations response: {0}, body: {1}".format(
            resp, body))
        return resp, body
