# Copyright 2017 Platform9 Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from sqlalchemy import Column, MetaData, Table
from sqlalchemy import Integer, DateTime, String, ForeignKey, Text
from migrate.changeset import UniqueConstraint


def define_tables(meta):
    credentials = Table(
        'credentials', meta,
        Column('created_at', DateTime(timezone=False), nullable=False),
        Column('updated_at', DateTime(timezone=False)),
        Column('deleted_at', DateTime(timezone=False)),
        Column('deleted', Integer),
        Column('owner_user_id', String(36)),
        Column('owner_project_id', String(36)),
        Column('id', String(36), nullable=False, primary_key=True),
        Column('name', String(255), nullable=False, primary_key=True),
        Column('value', Text(), nullable=False),
        mysql_engine='InnoDB', mysql_charset='utf8')

    credentials_association = Table(
        'credentials_association', meta,
        Column('created_at', DateTime(timezone=False), nullable=False),
        Column('updated_at', DateTime(timezone=False)),
        Column('deleted_at', DateTime(timezone=False)),
        Column('deleted', Integer),
        Column('owner_user_id', String(36)),
        Column('owner_project_id', String(36)),
        Column('id', Integer, primary_key=True, autoincrement=True),
        Column('project_id', String(36), nullable=False),
        Column('credential_id',
               String(36),
               ForeignKey('credentials.id'), nullable=False),
        UniqueConstraint(
            'project_id', 'deleted',
            name='uniq_credentials_association0'
                 'project_id0deleted'),
        mysql_engine='InnoDB', mysql_charset='utf8')
    return [credentials, credentials_association]


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    tables = define_tables(meta)

    for table in tables:
        table.create()


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    tables = define_tables(meta)

    for table in tables:
        table.drop()
