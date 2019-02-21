"""
Copyright 2017 Platform9 Systems Inc.(http://www.platform9.com)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
from six.moves import urllib

from keystoneauth1.access import service_catalog
from keystoneauth1.exceptions import EndpointNotFound
from keystoneauth1.identity import v3
from keystoneauth1 import session
from oslo_log import log as logging

from credsmgrclient.client import Client
from credsmgrclient.common import exceptions
from nova.exception import NotFound
from nova.virt.ec2.config import CONF

LOG = logging.getLogger(__name__)


class AwsCredentialsNotFound(NotFound):
    msg_fmt = "Aws credentials could not be found"


def _get_auth_url():
    # Use keystone v3 URL for getting token as v2 is going be deprecated.
    # Eg. http://<keystone_endpoint>/keystone_admin/v3
    conf_url = CONF.keystone_authtoken.identity_uri
    _url = urllib.parse.urlparse(conf_url.rstrip('/'))
    url_parts = _url.path.split('/')
    if 'v3' in url_parts:
        return conf_url
    elif url_parts[-1] == 'v2.0':
        url_parts[-1] = 'v3'
    else:
        url_parts.append('v3')
    # urlparse returns an instance of ParseResult which has read-only
    # attributes. ParseResult is just instance of tuple so we can
    # use it's parameters and reconstruct it to get desired URL.
    parse_params = list(_url)
    parse_params[2] = '/'.join(url_parts)
    return urllib.parse.ParseResult(*tuple(parse_params)).geturl()


def get_admin_session(CONF):
    # TODO(ssudake21): Cleanup nova conf keystone_authtoken section
    # to comply with standards
    auth_section = CONF.keystone_authtoken
    auth_params = {
        'auth_url': _get_auth_url(),
        'username': auth_section.admin_user,
        'password': auth_section.admin_password,
        'project_name': auth_section.admin_tenant_name,
        'user_domain_id': 'default',
        'project_domain_id': 'default'
    }
    auth = v3.Password(**auth_params)
    return session.Session(auth=auth)


def get_credentials_from_conf(CONF):
    secret_key = CONF.AWS.secret_key
    access_key = CONF.AWS.access_key
    if not access_key or not secret_key:
        raise AwsCredentialsNotFound()
    return dict(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key
    )


def _get_credsmgr_client(context=None):
    region_name = CONF.keystone_authtoken.region_name
    if context:
        token = context.auth_token
        sc = service_catalog.ServiceCatalogV2(context.service_catalog)
        credsmgr_endpoint = sc.url_for(
            service_type='credsmgr', region_name=region_name)
    else:
        session = get_admin_session(CONF)
        token = session.get_token()
        credsmgr_endpoint = session.get_endpoint(
            service_type='credsmgr', region_name=region_name)
    return Client(credsmgr_endpoint, token=token)


def get_credentials(context=None, project_id=None):
    # TODO(ssudake21): Add caching support
    # 1. Cache keystone endpoint
    # 2. Cache recently used AWS credentials
    if not (context or project_id):
        raise ValueError("Either of context or project_id should be mentioned")

    if project_id is None:
        project_id = context.project_id

    try:
        credsmgr_client = _get_credsmgr_client(context=context)
        resp, body = credsmgr_client.credentials.credentials_get(
            'aws', project_id)
    except (EndpointNotFound, exceptions.HTTPBadGateway):
        return get_credentials_from_conf(CONF)
    except exceptions.HTTPNotFound:
        if not CONF.AWS.use_credsmgr:
            return get_credentials_from_conf(CONF)
        raise
    return body


def get_credentials_all(context=None):
    try:
        credsmgr_client = _get_credsmgr_client(context=context)
        resp, body = credsmgr_client.credentials.credentials_list('aws')
        if not body:
            if not CONF.AWS.use_credsmgr:
                return [get_credentials_from_conf(CONF), ]
        for tenant, creds in body.items():
            creds['project_id'] = tenant
    except (EndpointNotFound, exceptions.HTTPBadGateway):
        return [get_credentials_from_conf(CONF), ]
    return body.values()
