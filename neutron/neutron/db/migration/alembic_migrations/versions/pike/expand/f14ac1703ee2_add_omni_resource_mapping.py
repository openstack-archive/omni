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

"""Add Omni resource mapping

Revision ID: f14ac1703ee2
Revises: 7d32f979895f
Create Date: 2018-09-04 21:04:41.357943

"""

# revision identifiers, used by Alembic.
revision = 'f14ac1703ee2'
down_revision = '7d32f979895f'

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

omni_resources_table = 'omni_resource_map'


def MediumText():
    return sa.Text().with_variant(mysql.MEDIUMTEXT(), 'mysql')


def upgrade():
    op.create_table(
        omni_resources_table,
        sa.Column('openstack_id',
                  sa.String(length=36),
                  nullable=False,
                  primary_key=True),
        sa.Column('omni_resource',
                  MediumText(),
                  nullable=False),
    )
