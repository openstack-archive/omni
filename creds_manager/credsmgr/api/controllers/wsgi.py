# Copyright 2011 OpenStack Foundation
# Copyright 2013 IBM Corp.
# Copyright 2017 Platform9 Systems.
#
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

import functools
import inspect
import six

from oslo_log import log as logging
from oslo_serialization import jsonutils
from oslo_utils import encodeutils
from oslo_utils import excutils
from oslo_utils import strutils
import webob
import webob.exc

from credsmgr.api.controllers import api_version_request as api_version
from credsmgr.api.controllers import versioned_method
from credsmgr import exception
from credsmgr import policy
from credsmgr import utils
from credsmgr.wsgi import common

LOG = logging.getLogger(__name__)

CREDSMGR_SERVICE = 'credsmgr'

SUPPORTED_CONTENT_TYPES = (
    'application/json',
)

_MEDIA_TYPE_MAP = {
    'application/json': 'json',
}


# name of attribute to keep version method information
VER_METHOD_ATTR = 'versioned_methods'

# Name of header used by clients to request a specific version
# of the REST API
API_VERSION_REQUEST_HEADER = 'OpenStack-API-Version'


class ActionDispatcher(object):
    """Maps method name to local methods through action name."""

    def dispatch(self, *args, **kwargs):
        """Find and call local method."""
        action = kwargs.pop('action', 'default')
        action_method = getattr(self, six.text_type(action), self.default)
        return action_method(*args, **kwargs)

    def default(self, data):
        raise NotImplementedError()


class TextDeserializer(ActionDispatcher):
    """Default request body deserialization."""

    def deserialize(self, datastring, action='default'):
        return self.dispatch(datastring, action=action)

    def default(self, datastring):
        return {}


class JSONDeserializer(TextDeserializer):

    def _from_json(self, datastring):
        try:
            return jsonutils.loads(datastring)
        except ValueError:
            msg = "cannot understand JSON"
            raise exception.MalformedRequestBody(reason=msg)

    def default(self, datastring):
        return {'body': self._from_json(datastring)}


class DictSerializer(ActionDispatcher):
    """Default request body serialization."""

    def serialize(self, data, action='default'):
        return self.dispatch(data, action=action)

    def default(self, data):
        return ""


class JSONDictSerializer(DictSerializer):
    """Default JSON request body serialization."""

    def default(self, data):
        return jsonutils.dump_as_bytes(data)


def serializers(**serializers):
    """Attaches serializers to a method.

    This decorator associates a dictionary of serializers with a
    method.  Note that the function attributes are directly
    manipulated; the method is not wrapped.
    """

    def decorator(func):
        if not hasattr(func, 'wsgi_serializers'):
            func.wsgi_serializers = {}
        func.wsgi_serializers.update(serializers)
        return func
    return decorator


def deserializers(**deserializers):
    """Attaches deserializers to a method.

    This decorator associates a dictionary of deserializers with a
    method.  Note that the function attributes are directly
    manipulated; the method is not wrapped.
    """

    def decorator(func):
        if not hasattr(func, 'wsgi_deserializers'):
            func.wsgi_deserializers = {}
        func.wsgi_deserializers.update(deserializers)
        return func
    return decorator


def response(code):
    """Attaches response code to a method.

    This decorator associates a response code with a method.  Note
    that the function attributes are directly manipulated; the method
    is not wrapped.
    """

    def decorator(func):
        func.wsgi_code = code
        return func
    return decorator


class ResponseObject(object):
    """Bundles a response object with appropriate serializers.

    Object that app methods may return in order to bind alternate
    serializers with a response object to be serialized.  Its use is
    optional.
    """

    def __init__(self, obj, code=None, headers=None, **serializers):
        """Binds serializers with an object.

        Takes keyword arguments akin to the @serializer() decorator
        for specifying serializers.  Serializers specified will be
        given preference over default serializers or method-specific
        serializers on return.
        """

        self.obj = obj
        self.serializers = serializers
        self._default_code = 200
        self._code = code
        self._headers = headers or {}
        self.serializer = None
        self.media_type = None

    def __getitem__(self, key):
        """Retrieves a header with the given name."""

        return self._headers[key.lower()]

    def __setitem__(self, key, value):
        """Sets a header with the given name to the given value."""

        self._headers[key.lower()] = value

    def __delitem__(self, key):
        """Deletes the header with the given name."""

        del self._headers[key.lower()]

    def _bind_method_serializers(self, meth_serializers):
        """Binds method serializers with the response object.

        Binds the method serializers with the response object.
        Serializers specified to the constructor will take precedence
        over serializers specified to this method.

        :param meth_serializers: A dictionary with keys mapping to
                                 response types and values containing
                                 serializer objects.
        """

        # We can't use update because that would be the wrong
        # precedence
        for mtype, serializer in meth_serializers.items():
            self.serializers.setdefault(mtype, serializer)

    def get_serializer(self, content_type, default_serializers=None):
        """Returns the serializer for the wrapped object.

        Returns the serializer for the wrapped object subject to the
        indicated content type.  If no serializer matching the content
        type is attached, an appropriate serializer drawn from the
        default serializers will be used.  If no appropriate
        serializer is available, raises InvalidContentType.
        """

        default_serializers = default_serializers or {}

        try:
            mtype = _MEDIA_TYPE_MAP.get(content_type, content_type)
            if mtype in self.serializers:
                return mtype, self.serializers[mtype]
            else:
                return mtype, default_serializers[mtype]
        except (KeyError, TypeError):
            raise exception.InvalidContentType(content_type=content_type)

    def preserialize(self, content_type, default_serializers=None):
        """Prepares the serializer that will be used to serialize.

        Determines the serializer that will be used and prepares an
        instance of it for later call.  This allows the serializer to
        be accessed by extensions for, e.g., template extension.
        """

        mtype, serializer = self.get_serializer(content_type,
                                                default_serializers)
        self.media_type = mtype
        self.serializer = serializer()

    def attach(self, **kwargs):
        """Attach slave templates to serializers."""

        if self.media_type in kwargs:
            self.serializer.attach(kwargs[self.media_type])

    def serialize(self, request, content_type, default_serializers=None):
        """Serializes the wrapped object.

        Utility method for serializing the wrapped object.  Returns a
        webob.Response object.
        """

        if self.serializer:
            serializer = self.serializer
        else:
            _mtype, _serializer = self.get_serializer(content_type,
                                                      default_serializers)
            serializer = _serializer()

        response = webob.Response()
        response.status_int = self.code
        for hdr, value in self._headers.items():
            response.headers[hdr] = six.text_type(value)
        response.headers['Content-Type'] = six.text_type(content_type)
        if self.obj is not None:
            body = serializer.serialize(self.obj)
            if isinstance(body, six.text_type):
                body = body.encode('utf-8')
            response.body = body

        return response

    @property
    def code(self):
        """Retrieve the response status."""

        return self._code or self._default_code

    @property
    def headers(self):
        """Retrieve the headers."""

        return self._headers.copy()


def action_peek_json(body):
    """Determine action to invoke."""

    try:
        decoded = jsonutils.loads(body)
    except ValueError:
        msg = "cannot understand JSON"
        raise exception.MalformedRequestBody(reason=msg)

    # Make sure there's exactly one key...
    if len(decoded) != 1:
        msg = "too many body keys"
        raise exception.MalformedRequestBody(reason=msg)

    # Return the action and the decoded body...
    return list(decoded.keys())[0]


class Fault(webob.exc.HTTPException):
    """Wrap webob.exc.HTTPException to provide API friendly response."""

    _fault_names = {400: "badRequest",
                    401: "unauthorized",
                    403: "forbidden",
                    404: "itemNotFound",
                    405: "badMethod",
                    409: "conflictingRequest",
                    413: "overLimit",
                    415: "badMediaType",
                    501: "notImplemented",
                    503: "serviceUnavailable"}

    def __init__(self, exception):
        """Create a Fault for the given webob.exc.exception."""
        self.wrapped_exc = exception
        self.status_int = exception.status_int

    @webob.dec.wsgify(RequestClass=common.Request)
    def __call__(self, req):
        """Generate a WSGI response based on the exception passed to ctor."""
        # Replace the body with fault details.
        code = self.wrapped_exc.status_int
        fault_name = self._fault_names.get(code, "computeFault")
        explanation = self.wrapped_exc.explanation
        fault_data = {
            fault_name: {
                'code': code,
                'message': explanation}}
        if code == 413:
            retry = self.wrapped_exc.headers.get('Retry-After', None)
            if retry:
                fault_data[fault_name]['retryAfter'] = retry

        if (not req.api_version_request.is_null() and not
           _is_legacy_endpoint(req)):
            self.wrapped_exc.headers[API_VERSION_REQUEST_HEADER] = (
                CREDSMGR_SERVICE + ' ' + req.api_version_request.get_string())
            self.wrapped_exc.headers['Vary'] = API_VERSION_REQUEST_HEADER

        content_type = req.best_match_content_type()
        serializer = {
            'application/json': JSONDictSerializer(),
        }[content_type]

        body = serializer.serialize(fault_data)
        if isinstance(body, six.text_type):
            body = body.encode('utf-8')
        self.wrapped_exc.body = body
        self.wrapped_exc.content_type = content_type
        _set_request_id_header(req, self.wrapped_exc.headers)

        return self.wrapped_exc

    def __str__(self):
        return self.wrapped_exc.__str__()


class ResourceExceptionHandler(object):
    """Context manager to handle Resource exceptions.

    Used when processing exceptions generated by API implementation
    methods (or their extensions).  Converts most exceptions to Fault
    exceptions, with the appropriate logging.
    """

    def __enter__(self):
        return None

    def __exit__(self, ex_type, ex_value, ex_traceback):
        if not ex_value:
            return True

        if isinstance(ex_value, exception.Unauthorized):
            msg = six.text_type(ex_value)
            raise Fault(webob.exc.HTTPForbidden(explanation=msg))
        elif isinstance(ex_value, exception.VersionNotFoundForAPIMethod):
            raise
        elif isinstance(ex_value, TypeError):
            exc_info = (ex_type, ex_value, ex_traceback)
            LOG.error('Exception handling resource: %s',
                      ex_value, exc_info=exc_info)
            raise Fault(webob.exc.HTTPBadRequest())
        elif isinstance(ex_value, Fault):
            LOG.info("Fault thrown: %s", six.text_type(ex_value))
            raise ex_value
        elif isinstance(ex_value, webob.exc.HTTPException):
            LOG.info("HTTP exception thrown: %s", six.text_type(ex_value))
            raise Fault(ex_value)

        # We didn't handle the exception
        return False


class Resource(common.Application):
    """WSGI app that handles (de)serialization and controller dispatch.

    WSGI app that reads routing information supplied by RoutesMiddleware
    and calls the requested action method upon its controller.  All
    controller action methods must accept a 'req' argument, which is the
    incoming wsgi.Request. If the operation is a PUT or POST, the controller
    method must also accept a 'body' argument (the deserialized request body).
    They may raise a webob.exc exception or return a dict, which will be
    serialized by requested content type.

    Exceptions derived from webob.exc.HTTPException will be automatically
    wrapped in Fault() to provide API friendly error responses.
    """
    # FIXME: to be enabled when microversion support is needed
    support_api_request_version = False

    def __init__(self, controller, action_peek=None, **deserializers):
        """Initialize Resource.

        :param controller: object that implement methods created by routes lib
        :param action_peek: dictionary of routines for peeking into an action
                            request body to determine the desired action
        """

        self.controller = controller

        default_deserializers = dict(json=JSONDeserializer)
        default_deserializers.update(deserializers)

        self.default_deserializers = default_deserializers
        self.default_serializers = dict(json=JSONDictSerializer)

        self.action_peek = dict(json=action_peek_json)
        self.action_peek.update(action_peek or {})

        # Copy over the actions dictionary
        self.wsgi_actions = {}
        if controller:
            self.register_actions(controller)

        # Save a mapping of extensions
        self.wsgi_extensions = {}
        self.wsgi_action_extensions = {}

    def register_actions(self, controller):
        """Registers controller actions with this resource."""

        actions = getattr(controller, 'wsgi_actions', {})
        for key, method_name in actions.items():
            self.wsgi_actions[key] = getattr(controller, method_name)

    def register_extensions(self, controller):
        """Registers controller extensions with this resource."""

        extensions = getattr(controller, 'wsgi_extensions', [])
        for method_name, action_name in extensions:
            # Look up the extending method
            extension = getattr(controller, method_name)

            if action_name:
                # Extending an action...
                if action_name not in self.wsgi_action_extensions:
                    self.wsgi_action_extensions[action_name] = []
                self.wsgi_action_extensions[action_name].append(extension)
            else:
                # Extending a regular method
                if method_name not in self.wsgi_extensions:
                    self.wsgi_extensions[method_name] = []
                self.wsgi_extensions[method_name].append(extension)

    def get_action_args(self, request_environment):
        """Parse dictionary created by routes library."""

        # NOTE(Vek): Check for get_action_args() override in the
        # controller
        if hasattr(self.controller, 'get_action_args'):
            return self.controller.get_action_args(request_environment)

        try:
            args = request_environment['wsgiorg.routing_args'][1].copy()
        except (KeyError, IndexError, AttributeError):
            return {}

        try:
            del args['controller']
        except KeyError:
            pass

        try:
            del args['format']
        except KeyError:
            pass

        return args

    def get_body(self, request):

        if len(request.body) == 0:
            LOG.debug("Empty body provided in request")
            return None, ''

        try:
            content_type = request.get_content_type()
        except exception.InvalidContentType:
            LOG.debug("Unrecognized Content-Type provided in request")
            return None, ''

        if not content_type:
            LOG.debug("No Content-Type provided in request")
            return None, ''

        return content_type, request.body

    def deserialize(self, meth, content_type, body):
        meth_deserializers = getattr(meth, 'wsgi_deserializers', {})
        try:
            mtype = _MEDIA_TYPE_MAP.get(content_type, content_type)
            if mtype in meth_deserializers:
                deserializer = meth_deserializers[mtype]
            else:
                deserializer = self.default_deserializers[mtype]
        except (KeyError, TypeError):
            raise exception.InvalidContentType(content_type=content_type)

        return deserializer().deserialize(body)

    def pre_process_extensions(self, extensions, request, action_args):
        # List of callables for post-processing extensions
        post = []

        for ext in extensions:
            if inspect.isgeneratorfunction(ext):
                response = None

                # If it's a generator function, the part before the
                # yield is the preprocessing stage
                try:
                    with ResourceExceptionHandler():
                        gen = ext(req=request, **action_args)
                        response = next(gen)
                except Fault as ex:
                    response = ex

                # We had a response...
                if response:
                    return response, []

                # No response, queue up generator for post-processing
                post.append(gen)
            else:
                # Regular functions only perform post-processing
                post.append(ext)

        # Run post-processing in the reverse order
        return None, reversed(post)

    def post_process_extensions(self, extensions, resp_obj, request,
                                action_args):
        for ext in extensions:
            response = None
            if inspect.isgenerator(ext):
                # If it's a generator, run the second half of
                # processing
                try:
                    with ResourceExceptionHandler():
                        response = ext.send(resp_obj)
                except StopIteration:
                    # Normal exit of generator
                    continue
                except Fault as ex:
                    response = ex
            else:
                # Regular functions get post-processing...
                try:
                    with ResourceExceptionHandler():
                        response = ext(req=request, resp_obj=resp_obj,
                                       **action_args)
                except exception.VersionNotFoundForAPIMethod:
                    # If an attached extension (@wsgi.extends) for the
                    # method has no version match its not an error. We
                    # just don't run the extends code
                    continue
                except Fault as ex:
                    response = ex

            # We had a response...
            if response:
                return response

        return None

    @webob.dec.wsgify(RequestClass=common.Request)
    def __call__(self, request):
        """WSGI method that controls (de)serialization and method dispatch."""
        LOG.info("%(method)s %(url)s",
                 {"method": request.method,
                  "url": request.url})

        if self.support_api_request_version:
            # Set the version of the API requested based on the header
            try:
                request.set_api_version_request(request.url)
            except exception.InvalidAPIVersionString as e:
                return Fault(webob.exc.HTTPBadRequest(
                    explanation=six.text_type(e)))
            except exception.InvalidGlobalAPIVersion as e:
                return Fault(webob.exc.HTTPNotAcceptable(
                    explanation=six.text_type(e)))

        # Identify the action, its arguments, and the requested
        # content type
        action_args = self.get_action_args(request.environ)
        action = action_args.pop('action', None)
        content_type, body = self.get_body(request)
        accept = request.best_match_content_type()

        # NOTE(Vek): Splitting the function up this way allows for
        #            auditing by external tools that wrap the existing
        #            function.  If we try to audit __call__(), we can
        #            run into troubles due to the @webob.dec.wsgify()
        #            decorator.
        return self._process_stack(request, action, action_args,
                                   content_type, body, accept)

    def _process_stack(self, request, action, action_args,
                       content_type, body, accept):
        """Implement the processing stack."""

        # Get the implementing method
        try:
            meth, extensions = self.get_method(request, action,
                                               content_type, body)
        except (AttributeError, TypeError):
            return Fault(webob.exc.HTTPNotFound())
        except KeyError as ex:
            msg = "There is no such action: %s" % ex.args[0]
            return Fault(webob.exc.HTTPBadRequest(explanation=msg))
        except exception.MalformedRequestBody:
            msg = "Malformed request body"
            return Fault(webob.exc.HTTPBadRequest(explanation=msg))

        if body:
            decoded_body = encodeutils.safe_decode(body, errors='ignore')
            msg = ("Action: '%(action)s', calling method: %(meth)s, body: "
                   "%(body)s") % {'action': action,
                                  'body': six.text_type(decoded_body),
                                  'meth': six.text_type(meth)}
            LOG.debug(strutils.mask_password(msg))
        else:
            LOG.debug("Calling method '%(meth)s'",
                      {'meth': six.text_type(meth)})

        # Now, deserialize the request body...
        try:
            if content_type:
                contents = self.deserialize(meth, content_type, body)
            else:
                contents = {}
        except exception.InvalidContentType:
            msg = "Unsupported Content-Type"
            return Fault(webob.exc.HTTPBadRequest(explanation=msg))
        except exception.MalformedRequestBody:
            msg = "Malformed request body"
            return Fault(webob.exc.HTTPBadRequest(explanation=msg))

        # Update the action args
        action_args.update(contents)

        project_id = action_args.pop("project_id", None)
        context = request.environ.get('credsmgr.context')
        if context and project_id and (project_id != context.project_id):
            msg = "Malformed request url"
            return Fault(webob.exc.HTTPBadRequest(explanation=msg))

        # Run pre-processing extensions
        response, post = self.pre_process_extensions(extensions,
                                                     request, action_args)

        if not response:
            try:
                with ResourceExceptionHandler():
                    action_result = self.dispatch(meth, request, action_args)
            except Fault as ex:
                response = ex

        if not response:
            # No exceptions; convert action_result into a
            # ResponseObject
            resp_obj = None
            if isinstance(action_result, dict) or action_result is None:
                resp_obj = ResponseObject(action_result)
            elif isinstance(action_result, ResponseObject):
                resp_obj = action_result
            else:
                response = action_result

            # Run post-processing extensions
            if resp_obj:
                _set_request_id_header(request, resp_obj)
                # Do a pre-serialize to set up the response object
                serializers = getattr(meth, 'wsgi_serializers', {})
                resp_obj._bind_method_serializers(serializers)
                if hasattr(meth, 'wsgi_code'):
                    resp_obj._default_code = meth.wsgi_code
                resp_obj.preserialize(accept, self.default_serializers)

                # Process post-processing extensions
                response = self.post_process_extensions(post, resp_obj,
                                                        request, action_args)

            if resp_obj and not response:
                response = resp_obj.serialize(request, accept,
                                              self.default_serializers)

        try:
            msg_dict = dict(url=request.url, status=response.status_int)
            msg = "%(url)s returned with HTTP %(status)d"
        except AttributeError as e:
            msg_dict = dict(url=request.url, e=e)
            msg = "%(url)s returned a fault: %(e)s"

        LOG.info(msg, msg_dict)

        if hasattr(response, 'headers'):
            for hdr, val in response.headers.items():
                # Headers must be utf-8 strings
                val = utils.convert_str(val)

                response.headers[hdr] = val

            if (not request.api_version_request.is_null() and
               not _is_legacy_endpoint(request)):
                response.headers[API_VERSION_REQUEST_HEADER] = (
                    CREDSMGR_SERVICE + ' ' +
                    request.api_version_request.get_string())
                response.headers['Vary'] = API_VERSION_REQUEST_HEADER

        return response

    def get_method(self, request, action, content_type, body):
        """Look up the action-specific method and its extensions."""

        # Look up the method
        try:
            if not self.controller:
                meth = getattr(self, action)
            else:
                meth = getattr(self.controller, action)
        except AttributeError as e:
            with excutils.save_and_reraise_exception(e) as ctxt:
                if (not self.wsgi_actions or action not in ['action',
                                                            'create',
                                                            'delete',
                                                            'update']):
                    LOG.exception('Get method error.')
                else:
                    ctxt.reraise = False
        else:
            return meth, self.wsgi_extensions.get(action, [])

        if action == 'action':
            # OK, it's an action; figure out which action...
            mtype = _MEDIA_TYPE_MAP.get(content_type)
            action_name = self.action_peek[mtype](body)
            LOG.debug("Action body: %s", body)
        else:
            action_name = action

        # Look up the action method
        return (self.wsgi_actions[action_name],
                self.wsgi_action_extensions.get(action_name, []))

    def dispatch(self, method, request, action_args):
        """Dispatch a call to the action-specific method."""

        try:
            return method(req=request, **action_args)
        except exception.VersionNotFoundForAPIMethod:
            # We deliberately don't return any message information
            # about the exception to the user so it looks as if
            # the method is simply not implemented.
            return Fault(webob.exc.HTTPNotFound())


def action(name):
    """Mark a function as an action.

    The given name will be taken as the action key in the body.

    This is also overloaded to allow extensions to provide
    non-extending definitions of create and delete operations.
    """

    def decorator(func):
        func.wsgi_action = name
        return func
    return decorator


def extends(*args, **kwargs):
    """Indicate a function extends an operation.

    Can be used as either::

        @extends
        def index(...):
            pass

    or as::

        @extends(action='resize')
        def _action_resize(...):
            pass
    """

    def decorator(func):
        # Store enough information to find what we're extending
        func.wsgi_extends = (func.__name__, kwargs.get('action'))
        return func

    # If we have positional arguments, call the decorator
    if args:
        return decorator(*args)

    # OK, return the decorator instead
    return decorator


class ControllerMetaclass(type):
    """Controller metaclass.

    This metaclass automates the task of assembling a dictionary
    mapping action keys to method names.
    """

    def __new__(mcs, name, bases, cls_dict):
        """Adds the wsgi_actions dictionary to the class."""

        # Find all actions
        actions = {}
        extensions = []
        # NOTE(geguileo): We'll keep a list of versioned methods that have been
        # added by the new metaclass (dictionary in attribute VER_METHOD_ATTR
        # on Controller class) and all the versioned methods from the different
        # base classes so we can consolidate them.
        versioned_methods = []

        # NOTE(cyeoh): This resets the VER_METHOD_ATTR attribute
        # between API controller class creations. This allows us
        # to use a class decorator on the API methods that doesn't
        # require naming explicitly what method is being versioned as
        # it can be implicit based on the method decorated. It is a bit
        # ugly.
        if bases != (object,) and VER_METHOD_ATTR in vars(Controller):
            # Get the versioned methods that this metaclass creation has added
            # to the Controller class
            versioned_methods.append(getattr(Controller, VER_METHOD_ATTR))
            # Remove them so next metaclass has a clean start
            delattr(Controller, VER_METHOD_ATTR)

        # start with wsgi actions from base classes
        for base in bases:
            actions.update(getattr(base, 'wsgi_actions', {}))

            # Get the versioned methods that this base has
            if VER_METHOD_ATTR in vars(base):
                versioned_methods.append(getattr(base, VER_METHOD_ATTR))

        for key, value in cls_dict.items():
            if not callable(value):
                continue
            if getattr(value, 'wsgi_action', None):
                actions[value.wsgi_action] = key
            elif getattr(value, 'wsgi_extends', None):
                extensions.append(value.wsgi_extends)

        # Add the actions and extensions to the class dict
        cls_dict['wsgi_actions'] = actions
        cls_dict['wsgi_extensions'] = extensions
        if versioned_methods:
            cls_dict[VER_METHOD_ATTR] = mcs.consolidate_vers(versioned_methods)

        return super(ControllerMetaclass, mcs).__new__(mcs, name, bases,
                                                       cls_dict)

    @staticmethod
    def consolidate_vers(versioned_methods):
        """Consolidates a list of versioned methods dictionaries."""
        if not versioned_methods:
            return {}
        result = versioned_methods.pop(0)
        for base_methods in versioned_methods:
            for name, methods in base_methods.items():
                method_list = result.setdefault(name, [])
                method_list.extend(methods)
                method_list.sort(reverse=True)
        return result


@six.add_metaclass(ControllerMetaclass)
class Controller(object):
    """Default controller."""

    _view_builder_class = None

    def __init__(self, view_builder=None):
        """Initialize controller with a view builder instance."""
        if view_builder:
            self._view_builder = view_builder
        elif self._view_builder_class:
            self._view_builder = self._view_builder_class()
        else:
            self._view_builder = None

    def __getattribute__(self, key):

        def version_select(*args, **kwargs):
            """Select and call the matching version of the specified method.

            Look for the method which matches the name supplied and version
            constraints and calls it with the supplied arguments.

            :returns: Returns the result of the method called
            :raises: VersionNotFoundForAPIMethod if there is no method which
                 matches the name and version constraints
            """

            # The first arg to all versioned methods is always the request
            # object. The version for the request is attached to the
            # request object
            if len(args) == 0:
                version_request = kwargs['req'].api_version_request
            else:
                version_request = args[0].api_version_request

            func_list = self.versioned_methods[key]
            for func in func_list:
                if version_request.matches_versioned_method(func):
                    # Update the version_select wrapper function so
                    # other decorator attributes like wsgi.response
                    # are still respected.
                    functools.update_wrapper(version_select, func.func)
                    return func.func(self, *args, **kwargs)

            # No version match
            raise exception.VersionNotFoundForAPIMethod(
                version=version_request)

        try:
            version_meth_dict = object.__getattribute__(self, VER_METHOD_ATTR)
        except AttributeError:
            # No versioning on this class
            return object.__getattribute__(self, key)

        if (version_meth_dict and key in
                object.__getattribute__(self, VER_METHOD_ATTR)):

            return version_select

        return object.__getattribute__(self, key)

    # NOTE(cyeoh): This decorator MUST appear first (the outermost
    # decorator) on an API method for it to work correctly
    @classmethod
    def api_version(cls, min_ver, max_ver=None, experimental=False):
        """Decorator for versioning API methods.

        Add the decorator to any method which takes a request object
        as the first parameter and belongs to a class which inherits from
        wsgi.Controller.

        :param min_ver: string representing minimum version
        :param max_ver: optional string representing maximum version
        """

        def decorator(f):
            obj_min_ver = api_version.APIVersionRequest(min_ver)
            if max_ver:
                obj_max_ver = api_version.APIVersionRequest(max_ver)
            else:
                obj_max_ver = api_version.APIVersionRequest()

            # Add to list of versioned methods registered
            func_name = f.__name__
            new_func = versioned_method.VersionedMethod(
                func_name, obj_min_ver, obj_max_ver, experimental, f)

            func_dict = getattr(cls, VER_METHOD_ATTR, {})
            if not func_dict:
                setattr(cls, VER_METHOD_ATTR, func_dict)

            func_list = func_dict.get(func_name, [])
            if not func_list:
                func_dict[func_name] = func_list
            func_list.append(new_func)
            # Ensure the list is sorted by minimum version (reversed)
            # so later when we work through the list in order we find
            # the method which has the latest version which supports
            # the version requested.
            # TODO(cyeoh): Add check to ensure that there are no overlapping
            # ranges of valid versions as that is ambiguous
            func_list.sort(reverse=True)

            # NOTE(geguileo): To avoid PEP8 errors when defining multiple
            # microversions of the same method in the same class we add the
            # api_version decorator to the function so it can be used instead,
            # thus preventing method redefinition errors.
            f.api_version = cls.api_version

            return f

        return decorator

    @staticmethod
    def is_valid_body(body, entity_name):
        if not (body and entity_name in body):
            return False

        def is_dict(d):
            try:
                d.get(None)
                return True
            except AttributeError:
                return False

        if not is_dict(body[entity_name]):
            return False

        return True

    @staticmethod
    def assert_valid_body(body, entity_name):
        # NOTE: After v1 api is deprecated need to merge 'is_valid_body' and
        #       'assert_valid_body' in to one method. Right now it is not
        #       possible to modify 'is_valid_body' to raise exception because
        #       in case of V1 api when 'is_valid_body' return False,
        #       'HTTPUnprocessableEntity' exception is getting raised and in
        #       V2 api 'HTTPBadRequest' exception is getting raised.
        if not Controller.is_valid_body(body, entity_name):
            raise webob.exc.HTTPBadRequest(
                explanation="Missing required element '%s' in "
                            "request body." % entity_name)

    @staticmethod
    def validate_name_and_description(body):
        name = body.get('name')
        if name is not None:
            if isinstance(name, six.string_types):
                body['name'] = name.strip()
            try:
                utils.check_string_length(body['name'], 'Name',
                                          min_length=0, max_length=255)
            except exception.InvalidInput as error:
                raise webob.exc.HTTPBadRequest(explanation=error.msg)

        description = body.get('description')
        if description is not None:
            try:
                utils.check_string_length(description, 'Description',
                                          min_length=0, max_length=255)
            except exception.InvalidInput as error:
                raise webob.exc.HTTPBadRequest(explanation=error.msg)

    @staticmethod
    def validate_string_length(value, entity_name, min_length=0,
                               max_length=None, remove_whitespaces=False):
        """Check the length of specified string.

        :param value: the value of the string
        :param entity_name: the name of the string
        :param min_length: the min_length of the string
        :param max_length: the max_length of the string
        :param remove_whitespaces: True if trimming whitespaces is needed
                                   else False
        """
        if isinstance(value, six.string_types) and remove_whitespaces:
            value = value.strip()
        try:
            utils.check_string_length(value, entity_name,
                                      min_length=min_length,
                                      max_length=max_length)
        except exception.InvalidInput as error:
            raise webob.exc.HTTPBadRequest(explanation=error.msg)

    @staticmethod
    def get_policy_checker(prefix):
        def policy_checker(req, action, resource=None):
            ctxt = req.environ['credsmgr.context']
            target = {
                'project_id': ctxt.project_id,
                'user_id': ctxt.user_id,
            }
            if resource:
                target.update(resource)

            _action = '%s:%s' % (prefix, action)
            policy.enforce(ctxt, _action, target)
            return ctxt
        return policy_checker


def _set_request_id_header(req, headers):
    context = req.environ.get('credsmgr.context')
    if context:
        headers['x-compute-request-id'] = context.request_id


def _is_legacy_endpoint(request):
    version_str = request.api_version_request.get_string()
    return '1.0' in version_str or '2.0' in version_str
