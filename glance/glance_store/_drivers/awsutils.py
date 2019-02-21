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
from keystoneauth1.access import service_catalog
from keystoneauth1.exceptions import EndpointNotFound

from credsmgrclient.client import Client
from credsmgrclient.common import exceptions as credsmgr_ex
from glance_store import exceptions as glance_ex


from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class AwsCredentialsNotFound(glance_ex.GlanceStoreException):
    message = "Aws credentials could not be found"


def get_credentials_from_conf(conf):
    secret_key = conf.aws.secret_key
    access_key = conf.aws.access_key
    if not access_key or not secret_key:
        raise AwsCredentialsNotFound()
    return dict(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key
    )


def get_credentials(context, tenant, conf=None):
    # TODO(ssudake21): Add caching support
    # 1. Cache keystone endpoint
    # 2. Cache recently used AWS credentials
    try:
        if context is None or tenant is None:
            raise glance_ex.AuthorizationFailure()
        sc = service_catalog.ServiceCatalogV2(context.service_catalog)
        region_name = conf.keystone_credentials.region_name
        credsmgr_endpoint = sc.url_for(
            service_type='credsmgr', region_name=region_name)
        token = context.auth_token
        credsmgr_client = Client(credsmgr_endpoint, token=token)
        resp, body = credsmgr_client.credentials.credentials_get(
            'aws', tenant)
    except (EndpointNotFound, credsmgr_ex.HTTPBadGateway,
            credsmgr_ex.HTTPNotFound):
        if conf is not None:
            return get_credentials_from_conf(conf)
        raise AwsCredentialsNotFound()
    return body
