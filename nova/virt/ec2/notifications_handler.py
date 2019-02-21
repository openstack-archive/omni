"""
Copyright (c) 2014 Thoughtworks.
Copyright (c) 2018 Platform9 Systems Inc.
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
eventlet.monkey_patch()  # noqa

from six.moves import urllib

import boto3

from kombu import Connection
from kombu import Exchange
from kombu.mixins import ConsumerMixin
from kombu import Queue

from oslo_config import cfg
from oslo_log import log as logging

from nova.virt.ec2.credshelper import get_credentials_all

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


def _get_ec2_conn(creds):
    ec2_conn = boto3.client(
        "ec2", region_name=CONF.AWS.region_name,
        aws_access_key_id=creds['aws_access_key_id'],
        aws_secret_access_key=creds['aws_secret_access_key'])
    return ec2_conn


def _delete_keypairs_by_name(key_name):
    credentials = get_credentials_all()
    for creds in credentials:
        ec2_conn = _get_ec2_conn(creds)
        ec2_conn.delete_key_pair(KeyName=key_name)


class NovaNotificationsHandler(ConsumerMixin):
    nova_exchange = 'nova'
    routing_key = 'notifications.info'
    queue_name = 'notifications.omni.keypair'
    events_of_interest = ['keypair.delete.start', 'keypair.delete.end']
    instance_events = ['compute.instance.update']

    def __init__(self):
        _transport_url = CONF.transport_url
        # Change tranport for Kombu as it accepts different
        # names for transport.
        url_params = list(urllib.parse.urlparse(_transport_url))
        url_params[0] = 'amqp'
        self.broker_uri = urllib.parse.ParseResult(*tuple(url_params)).geturl()
        self.connection = Connection(self.broker_uri, heartbeat=60)

    def get_consumers(self, consumer, channel):
        exchange = Exchange(self.nova_exchange, type="topic", durable=False)
        queue = Queue(self.queue_name, exchange, routing_key=self.routing_key,
                      durable=False, auto_delete=True, no_ack=True)
        return [consumer(queue, callbacks=[self.handle_notification])]

    def _handle_keypair_notification(self, message_body):
        key_name = message_body['payload']['key_name']
        try:
            LOG.info('Deleting %s keypair', key_name)
            _delete_keypairs_by_name(key_name)
        except Exception:
            LOG.exception('Could not delete %s', key_name)

    def handle_notification(self, body, message):
        LOG.debug('Received notification - %r', body)
        if 'event_type' in body and body['event_type'] in \
                self.events_of_interest:
            self._handle_keypair_notification(body)
        message.ack()
