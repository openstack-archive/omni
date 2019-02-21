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
from credsmgrclient.common import exceptions

from cinder.volume.drivers.aws.config import CONF
from cinder.volume.drivers.aws.exception import AwsCredentialsNotFound

from oslo_log import log as logging

LOG = logging.getLogger(__name__)


def get_credentials_from_conf(CONF):
    secret_key = CONF.AWS.secret_key
    access_key = CONF.AWS.access_key
    if not access_key or not secret_key:
        raise AwsCredentialsNotFound()
    return dict(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key
    )


def get_credentials(context, project_id=None):
    # TODO(ssudake21): Add caching support
    # 1. Cache keystone endpoint
    # 2. Cache recently used AWS credentials
    try:
        sc = service_catalog.ServiceCatalogV2(context.service_catalog)
        credsmgr_endpoint = sc.url_for(
            service_type='credsmgr', region_name=CONF.os_region_name)
        token = context.auth_token
        credsmgr_client = Client(credsmgr_endpoint, token=token)
        if not project_id:
            project_id = context.project_id
        resp, body = credsmgr_client.credentials.credentials_get(
            'aws', project_id)
    except (EndpointNotFound, exceptions.HTTPBadGateway):
        return get_credentials_from_conf(CONF)
    except exceptions.HTTPNotFound:
        if not CONF.AWS.use_credsmgr:
            return get_credentials_from_conf(CONF)
        raise
    return body
