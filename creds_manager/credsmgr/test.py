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

import fixtures

from oslo_config import cfg
from oslo_log import log as logging
from oslotest import moxstubout
import testtools

from credsmgr.tests import utils

CONF = cfg.CONF
logging.register_options(CONF)
logging.setup(CONF, 'credsmgr')

_DB_CACHE = None


class Database(fixtures.Fixture):
    def __init__(self, db_api, db_migrate, sql_connection):
        self.sql_connection = sql_connection
        self.engine = db_api.get_engine()
        self.engine.dispose()

    def setUp(self):
        super(Database, self).setUp()
        conn = self.engine.connect()
        conn.connection.executescript(self._DB)
        self.addCleanup(self.engine.dispose)


class TestCase(testtools.TestCase):
    """
    Base class for all credsmgr unit tests
    """

    def setUp(self):
        super(TestCase, self).setUp()
        self.useFixture(fixtures.FakeLogger('credsmgr'))
        CONF.set_default('connection', 'sqlite://', 'database')
        CONF.set_default('sqlite_synchronous', True, 'database')

        utils.setup_dummy_db()
        self.addCleanup(utils.reset_dummy_db)

        mox_fixture = self.useFixture(moxstubout.MoxStubout())
        self.mox = mox_fixture.mox
        self.stubs = mox_fixture.stubs


class DBObject(dict):
    def __init__(self, **kwargs):
        super(DBObject, self).__init__(kwargs)

    def __getattr__(self, item):
        return self[item]
