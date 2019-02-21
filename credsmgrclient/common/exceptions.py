"""
Copyright 2017 Platform9 Systems Inc.(http://www.platform9.com)
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

import sys

import six


class _BaseException(Exception):
    """An error occurred."""
    def __init__(self, message=None):
        super(_BaseException, self).__init__()
        self.message = message


class InvalidEndpoint(_BaseException):
    """The provided endpoint is invalid."""


class InvalidToken(_BaseException):
    """Provided token is invalid or token not provided"""


class CommunicationError(_BaseException):
    """Unable to communicate with server."""


class InvalidJson(_BaseException):
    "Provided JSON is invalid"


class HTTPException(Exception):
    """Base exception for all HTTP-derived exceptions."""
    code = 'N/A'

    def __init__(self, details=None):
        super(HTTPException, self).__init__()
        self.details = details or self.__class__.__name__

    def __str__(self):
        return "%s (HTTP %s)" % (self.details, self.code)


class HTTPBadRequest(HTTPException):
    code = 400


class HTTPUnauthorized(HTTPException):
    code = 401


class HTTPForbidden(HTTPException):
    code = 403


class HTTPNotFound(HTTPException):
    code = 404


class HTTPMethodNotAllowed(HTTPException):
    code = 405


class HTTPConflict(HTTPException):
    code = 409


class HTTPOverLimit(HTTPException):
    code = 413


class HTTPInternalServerError(HTTPException):
    code = 500


class HTTPNotImplemented(HTTPException):
    code = 501


class HTTPBadGateway(HTTPException):
    code = 502


class HTTPServiceUnavailable(HTTPException):
    code = 503


_code_map = {}
for obj_name in dir(sys.modules[__name__]):
    if obj_name.startswith('HTTP'):
        obj = getattr(sys.modules[__name__], obj_name)
        _code_map[obj.code] = obj


def from_response(response, body=None):
    """Return an instance of an HTTPException based on httplib response."""
    cls = _code_map.get(response.status_code, HTTPException)
    if body and 'json' in response.headers['content-type']:
        # Iterate over the nested objects and retrieve the "message" attribute.
        messages = [obj.get('message') for obj in response.json().values()]
        # Join all of the messages together nicely and filter out any objects
        # that don't have a "message" attr.
        details = '\n'.join(i for i in messages if i is not None)
        return cls(details=details)
    elif body:
        if six.PY3:
            body = body.decode('utf-8')
        details = body.replace('\n\n', '\n')
        return cls(details=details)
    return cls()
