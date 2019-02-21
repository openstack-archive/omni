# Copyright (c) 2011 OpenStack Foundation
# All Rights Reserved.
#
# Copyright (c) 2017 Platform9 Systems
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

"""Policy Engine For Credsmgr"""


from oslo_config import cfg
from oslo_policy import opts as policy_opts
from oslo_policy import policy

from credsmgr import exception

CONF = cfg.CONF
policy_opts.set_defaults(cfg.CONF, 'policy.json')

_ENFORCER = None


def init():
    global _ENFORCER
    if not _ENFORCER:
        _ENFORCER = policy.Enforcer(CONF)


def enforce(context, action, target):
    """Verifies that the action is valid on the target in this context.

       :param context: credsmgr context
       :param action: string representing the action to be checked
           this should be colon separated for clarity.
           i.e. ``compute:create_instance``,
           ``compute:attach_volume``,
           ``volume:attach_volume``

       :param object: dictionary representing the object of the action
           for object creation this should be a dictionary representing the
           location of the object e.g. ``{'project_id': context.project_id}``

       :raises PolicyNotAuthorized: if verification fails.

    """
    init()

    return _ENFORCER.enforce(action,
                             target,
                             context.to_policy_values(),
                             do_raise=True,
                             exc=exception.PolicyNotAuthorized,
                             action=action)


def check_is_admin(roles, context=None):
    """Whether or not user is admin according to policy setting.

    """
    init()

    # include project_id on target to avoid KeyError if context_is_admin
    # policy definition is missing, and default admin_or_owner rule
    # attempts to apply.
    target = {'project_id': ''}
    if context is None:
        credentials = {'roles': roles}
    else:
        credentials = context.to_dict()

    return _ENFORCER.enforce('context_is_admin', target, credentials)
