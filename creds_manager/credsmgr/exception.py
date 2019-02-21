# Copyright 2017 Platform9 Systems
# All Rights Reserved.
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
"""Credsmgr base exception handling.

Includes decorator for re-raising Credsmgr-type exceptions.

SHOULD include dedicated exception logging.

"""

import sys

from oslo_config import cfg
from oslo_log import log as logging

import six

LOG = logging.getLogger(__name__)

CONF = cfg.CONF


class CredsMgrException(Exception):
    """Base Credsmgr Exception

    To correctly use this class, inherit from it and define
    a 'msg_fmt' property. That msg_fmt will get printf'd
    with the keyword arguments provided to the constructor.

    """
    msg_fmt = "An unknown exception occurred."
    code = 500
    headers = {}
    safe = False

    def __init__(self, message=None, **kwargs):
        self.kwargs = kwargs

        if 'code' not in self.kwargs:
            try:
                self.kwargs['code'] = self.code
            except AttributeError:
                pass

        if not message:
            try:
                message = self.msg_fmt % kwargs

            except Exception:
                exc_info = sys.exc_info()
                # kwargs doesn't match a variable in the message
                # log the issue and the kwargs
                LOG.exception('Exception in string format operation')
                for name, value in six.iteritems(kwargs):
                    LOG.error("%s: %s" % (name, value))  # noqa

                if CONF.fatal_exception_format_errors:
                    six.reraise(*exc_info)
                else:
                    # at least get the core message out if something happened
                    message = self.msg_fmt

        self.message = message
        super(CredsMgrException, self).__init__(message)

    def format_message(self):
        # NOTE: use the first argument to the python Exception object
        # which should be our full CredsMgrException message, (see __init__)
        return self.args[0]


class APIException(CredsMgrException):
    msg_fmt = "Error while requesting %(service)s API."

    def __init__(self, message=None, **kwargs):
        if 'service' not in kwargs:
            kwargs['service'] = 'unknown'
        super(APIException, self).__init__(message, **kwargs)


class APITimeout(APIException):
    msg_fmt = "Timeout while requesting %(service)s API."


class Conflict(CredsMgrException):
    msg_fmt = "Conflict"
    code = 409


class Invalid(CredsMgrException):
    msg_fmt = "Bad Request - Invalid Parameters"
    code = 400


class InvalidName(Invalid):
    msg_fmt = "An invalid 'name' value was provided. "\
              "The name must be: %(reason)s"


class InvalidInput(Invalid):
    msg_fmt = "Invalid input received: %(reason)s"


class InvalidAPIVersionString(Invalid):
    msg_fmt = "API Version String %(version)s is of invalid format. Must "\
              "be of format MajorNum.MinorNum."


class MalformedRequestBody(CredsMgrException):
    msg_fmt = "Malformed message body: %(reason)s"


# NOTE: NotFound should only be used when a 404 error is
# appropriate to be returned
class NotFound(CredsMgrException):
    msg_fmt = "Resource could not be found."
    code = 404


class ConfigNotFound(NotFound):
    msg_fmt = "Could not find config at %(path)s"


class Forbidden(CredsMgrException):
    msg_fmt = "Forbidden"
    code = 403


class AdminRequired(Forbidden):
    msg_fmt = "User does not have admin privileges"


class PolicyNotAuthorized(Forbidden):
    msg_fmt = "Policy doesn't allow %(action)s to be performed."


class PasteAppNotFound(CredsMgrException):
    msg_fmt = "Could not load paste app '%(name)s' from %(path)s"


class InvalidContentType(Invalid):
    msg_fmt = "Invalid content type %(content_type)s."


class VersionNotFoundForAPIMethod(Invalid):
    msg_fmt = "API version %(version)s is not supported on this method."


class InvalidGlobalAPIVersion(Invalid):
    msg_fmt = "Version %(req_ver)s is not supported by the API. Minimum " \
              "is %(min_ver)s and maximum is %(max_ver)s."


class ApiVersionsIntersect(Invalid):
    msg_fmt = "Version of %(name) %(min_ver) %(max_ver) intersects " \
              "with another versions."


class ValidationError(Invalid):
    msg_fmt = "%(detail)s"


class Unauthorized(CredsMgrException):
    msg_fmt = "Not authorized."
    code = 401


class NoResources(CredsMgrException):
    msg_fmt = "No resources available"


class CredentialNotFound(NotFound):
    msg_fmt = "Credential with id %(cred_id)s could not be found."


class CredentialAssociationNotFound(NotFound):
    msg_fmt = "Credential associated with tenant %(tenant_id)s "\
              "could not be found."


class CredentialAssociationExists(Conflict):
    msg_fmt = "Credential associated with tenant %(tenant_id)s exists"


class CredentialExists(Conflict):
    msg_fmt = "credentials with provided parameters already exists"
