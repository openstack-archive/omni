# Copyright 2018 OpenStack Foundation
# Copyright 2018 Platform9 Systems Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

from neutron.db import api as db_api
from neutron.db.models import omni_resources
from oslo_log import log as logging


LOG = logging.getLogger(__name__)


def add_mapping(openstack_id, omni_resource):
    LOG.debug('Adding mapping as - %s --> %s', openstack_id, omni_resource)
    session = db_api.get_session()
    with db_api.autonested_transaction(session) as tx:
        check_existing = tx.session.query(omni_resources.OmniResources).\
            filter_by(openstack_id=openstack_id).first()
        if check_existing:
            LOG.info('Updating to add %s-%s since already present',
                     openstack_id, omni_resource)
            check_existing.omni_resource = omni_resource
            tx.session.flush()
        else:
            mapping = omni_resources.OmniResources(openstack_id, omni_resource)
            tx.session.add(mapping)


def get_omni_resource(openstack_id):
    session = db_api.get_reader_session()
    result = session.query(omni_resources.OmniResources).filter_by(
        openstack_id=openstack_id).first()
    if not result:
        return None
    return result.omni_resource


def delete_mapping(openstack_id):
    LOG.debug('Deleting mapping for - %s', openstack_id)
    session = db_api.get_session()
    with db_api.autonested_transaction(session) as tx:
        mapping = tx.session.query(omni_resources.OmniResources).filter_by(
            openstack_id=openstack_id).first()
        if mapping:
            tx.session.delete(mapping)
