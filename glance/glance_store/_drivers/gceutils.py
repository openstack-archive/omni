"""
Copyright (c) 2017 Platform9 Systems Inc.
Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""

from googleapiclient.discovery import build
from oauth2client.client import GoogleCredentials
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


def get_gce_service(service_key):
    """Returns GCE compute resource object for interacting with GCE API
    :param service_key: string, Path of service key obtained from
        https://console.cloud.google.com/apis/credentials
    """
    credentials = GoogleCredentials.from_stream(service_key)
    service = build('compute', 'v1', credentials=credentials)
    return service


def get_images(compute, project):
    """Return public images info from GCE
    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    """
    response = compute.images().list(project=project,
                                     filter="status eq READY").execute()
    if 'items' not in response:
        return []
    imgs = filter(lambda img: 'deprecated' not in img, response['items'])
    return imgs


def get_image(compute, project, name):
    """Return public images info from GCE
    :param compute: GCE compute resource object using googleapiclient.discovery
    :param project: string, GCE Project Id
    """
    result = compute.images().get(project=project, image=name).execute()
    return result
