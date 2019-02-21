"""
Copyright 2018 Platform9 Systems Inc.(http://www.platform9.com).

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""

import mock


def get_fake_context():
    """Get fake context for all operations."""
    context = mock.Mock()
    context.current = {}
    context.current['name'] = "fake_context_name"
    context.current['id'] = "fake_context_id"
    context.current['subnets'] = {}
    context.current['ip_version'] = 4
    context.current['cidr'] = "192.168.1.0/24"
    context.current['tenant_id'] = "fake_tenant_id"
    context.current['project_id'] = "fake_tenant_id"
    context.current['network_id'] = "fake_network_id"

    context.original = {}
    context.original['name'] = "old_context_name"

    context.network.current = {}
    context.network.current['id'] = "fake_network_context_id"
    context.network.current['name'] = "fake_network_context_name"
    context.network.current['availability_zone_hints'] = ["us-east-1a"]

    context._plugin_context = {}
    context._plugin_context['tenant'] = "fake_tenant_id"
    context._plugin_context['auth_token'] = "fake_auth_token"
    return context


def fake_get_credentials(*args, **kwargs):
    """Mocking class to get credentials."""
    return {
        'aws_access_key_id': 'fake_access_key_id',
        'aws_secret_access_key': 'fake_access_key'
    }


class FakeSession(object):
    """Fake session class to mock Keystone session."""

    def get_token(*args, **kwargs):
        """Fake method to mock keystone's get_token function."""
        return "fake_token"

    def get_endpoint(*args, **kwargs):
        """Fake method to mock get_endpoint method."""
        return "http://fake_endpoint"


mock_send_value = ["us-east-1a", "us-east-1b", "us-east-1c", "us-east-1d",
                   "us-east-1e", "us-east-1f"]
