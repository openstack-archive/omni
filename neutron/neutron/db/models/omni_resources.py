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

from neutron_lib.db import model_base
import sqlalchemy as sa
from sqlalchemy.dialects import mysql


def MediumText():
    return sa.Text().with_variant(mysql.MEDIUMTEXT(), 'mysql')


class OmniResources(model_base.BASEV2):
    __tablename__ = 'omni_resource_map'
    openstack_id = sa.Column(sa.String(36), nullable=False, primary_key=True)
    # Omni resource field is set to MEDIUMTEXT because so that it can be used
    # to store larger information e.g. security groups along with group rules
    # for different VPCs. For networks and subnets the table will simply be a
    # mapping from OpenStack ID to public cloud ID.
    omni_resource = sa.Column(MediumText(), nullable=False)

    def __repr__(self):
        return "<%s(%s, %s)>" % (self.__class__.__name__, self.openstack_id,
                                 self.omni_resource)

    def __init__(self, openstack_id, omni_resource):
        self.openstack_id = openstack_id
        self.omni_resource = omni_resource
