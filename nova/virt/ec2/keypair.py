"""
Copyright (c) 2014 Thoughtworks.
Copyright (c) 2017 Platform9 Systems Inc.
All Rights reserved
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

import eventlet
eventlet.monkey_patch()

from kombu import Connection
from kombu import Exchange
from kombu.mixins import ConsumerMixin
from kombu import Queue

from oslo_config import cfg
from oslo_log import log as logging

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

rabbit_opts = [
    cfg.StrOpt('rabbit_userid'),
    cfg.StrOpt('rabbit_password'),
    cfg.StrOpt('rabbit_host'),
    cfg.StrOpt('rabbit_port'),
]

CONF.register_opts(rabbit_opts)


class KeyPairNotifications(ConsumerMixin):
    nova_exchange = 'nova'
    routing_key = 'notifications.info'
    queue_name = 'notifications.omni.keypair'
    events_of_interest = ['keypair.delete.start', 'keypair.delete.end']

    def __init__(self, aws_connection, transport='amqp'):
        self.ec2_conn = aws_connection
        self.broker_uri = \
            "{transport}://{username}:{password}@{rabbit_host}:{rabbit_port}"\
            .format(transport=transport,
                    username=CONF.rabbit_userid,
                    password=CONF.rabbit_password,
                    rabbit_host=CONF.rabbit_host,
                    rabbit_port=CONF.rabbit_port)
        self.connection = Connection(self.broker_uri)

    def get_consumers(self, consumer, channel):
        exchange = Exchange(self.nova_exchange, type="topic", durable=False)
        queue = Queue(self.queue_name, exchange, routing_key=self.routing_key,
                      durable=False, auto_delete=True, no_ack=True)
        return [consumer(queue, callbacks=[self.handle_notification])]

    def handle_notification(self, body, message):
        if 'event_type' in body and body['event_type'] in \
                self.events_of_interest:
            LOG.debug('Body: %r' % body)
            key_name = body['payload']['key_name']
            try:
                LOG.info('Deleting %s keypair', key_name)
                self.ec2_conn.delete_key_pair(key_name)
            except Exception:
                LOG.exception('Could not delete %s', key_name)
