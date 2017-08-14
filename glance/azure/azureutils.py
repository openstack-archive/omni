"""
Copyright (c) 2017 Platform9 Systems Inc. (http://www.platform9.com)
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

from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.compute import ComputeManagementClient

AZURE_PUBLISHERS = ['Canonical', 'CoreOS', 'credativ', 'OpenLogic', 'RedHat',
                    'SUSE', 'MicrosoftVisualStudio', 'MicrosoftSQLServer']

AZURE_OFFERS = ['UbuntuServer', 'CoreOS', 'Debian', 'CentOS', 'RHEL', 'SLES',
                'Windows', 'SQL2012SP3-WS2012R2', 'SQL2016SP1-WS2016']


def get_azure_client(tenant_id, client_id, client_secret, subscription_id):
    credentials = ServicePrincipalCredentials(
        client_id=client_id, secret=client_secret, tenant=tenant_id)
    client = ComputeManagementClient(credentials, subscription_id)
    return client


def get_vm_images(compute, region):
    images = []
    publisher_list = compute.virtual_machine_images.list_publishers(region)
    for publisher in publisher_list:
        if publisher.name in AZURE_PUBLISHERS:
            offers_list = compute.virtual_machine_images.list_offers(
                region, publisher.name)
            for offer in offers_list:
                if offer.name in AZURE_OFFERS:
                    skus_list = compute.virtual_machine_images.list_skus(
                        region, publisher.name, offer.name)
                    for sku in skus_list:
                        result_list = compute.virtual_machine_images.list(
                            region, publisher.name, offer.name, sku.name)
                        if len(result_list) > 0:
                            version = result_list.pop()
                            result_get = compute.virtual_machine_images.get(
                                region, publisher.name, offer.name, sku.name,
                                version.name)
                            images.append(result_get.__dict__)
    return images
