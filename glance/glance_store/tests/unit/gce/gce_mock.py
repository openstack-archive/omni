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

import os

from apiclient.http import HttpMock
from googleapiclient.discovery import build

DATA_DIR = os.path.dirname(os.path.abspath(__file__)) + '/data'


def get_gce_service(service_key):
    http = HttpMock(DATA_DIR + '/service/service_data.json', {'status': '200'})
    service = build('compute', 'v1', http=http, developerKey=service_key)
    return service


def get_image(compute, project, name):
    http = HttpMock(DATA_DIR + '/image/get_image.json', {'status': '200'})
    request = compute.images().get(project=project, image=name)
    response = request.execute(http=http)
    return response
