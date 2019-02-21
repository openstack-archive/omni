# Copyright 2017 Platform9 Systems, Inc.
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
"""
SQLAlchemy models for credsmgr data.
"""

from oslo_config import cfg
from oslo_db.sqlalchemy import models
from oslo_utils import timeutils

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, Text
from sqlalchemy import ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship

CONF = cfg.CONF
BASE = declarative_base()


class CredsMgrBase(models.TimestampMixin, models.SoftDeleteMixin,
                   models.ModelBase):
    """Base class for Credsmgr Models."""

    __table_args__ = {'mysql_engine': 'InnoDB'}

    owner_user_id = Column(String(36), nullable=False)
    owner_project_id = Column(String(36), nullable=False)
    metadata = None


class Credential(BASE, CredsMgrBase):
    __tablename__ = 'credentials'

    id = Column(String(36), nullable=False, primary_key=True)
    name = Column(String(255), nullable=False, primary_key=True)
    value = Column(Text(), nullable=False)

    def soft_delete(self, session):
        # NOTE(ssudake21): oslo_db directly assigns object id to deleted field.
        # Here we have string, so need to override soft_delete method.
        self.deleted = 1
        self.deleted_at = timeutils.utcnow()
        self.save(session=session)


class CredentialsAssociation(BASE, CredsMgrBase):
    """Represents credentials association with tenant"""
    __tablename__ = 'credentials_association'
    __table_args__ = (
        UniqueConstraint(
            'project_id', 'deleted',
            name='uniq_credentials_association0'
                 'project_id0deleted'
        ), {})

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(String(36), nullable=False)
    credential_id = Column(
        String(36), ForeignKey('credentials.id'), nullable=False)
    primaryjoin = 'and_({0}.{1} == {2}.id, {2}.deleted == 0)'.format(
        'CredentialsAssociation', 'credential_id', 'Credential')
    credentials = relationship('Credential', uselist=True,
                               primaryjoin=primaryjoin)


def register_models(engine):
    """Creates database tables for all models with the given engine."""
    models = (Credential, CredentialsAssociation)
    for model in models:
        model.metadata.create_all(engine)


def unregister_models(engine):
    """Drops database tables for all models with the given engine."""
    models = (Credential, CredentialsAssociation)
    for model in models:
        model.metadata.drop_all(engine)
