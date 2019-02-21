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
"""Database setup and migration commands."""

import os
import threading

from oslo_config import cfg
from oslo_db import options
from stevedore import driver

from credsmgr.db.sqlalchemy import api as db_api


INIT_VERSION = 00

_IMPL = None
_LOCK = threading.Lock()

print("Set defaults")
options.set_defaults(cfg.CONF)

MIGRATE_REPO_PATH = os.path.join(
    os.path.abspath(os.path.dirname(__file__)),
    'sqlalchemy',
    'migrate_repo',
)


def get_backend():
    global _IMPL
    if _IMPL is None:
        with _LOCK:
            if _IMPL is None:
                _IMPL = driver.DriverManager(
                    "credsmgr.database.migration_backend",
                    cfg.CONF.database.backend).driver
    return _IMPL


def db_sync(version=None, init_version=INIT_VERSION, engine=None):
    """Migrate the database to `version` or the most recent version."""

    if engine is None:
        engine = db_api.get_engine()

    print("DB sync")
    current_db_version = get_backend().db_version(engine,
                                                  MIGRATE_REPO_PATH,
                                                  init_version)

    # TODO(e0ne): drop version validation when new oslo.db will be released
    if version and int(version) < current_db_version:
        msg = 'Database schema downgrade is not allowed.'
        raise Exception(msg)
    return get_backend().db_sync(engine=engine,
                                 abs_path=MIGRATE_REPO_PATH,
                                 version=version,
                                 init_version=init_version)
