""" 4.4 OAUTH 2 for devices

    Applications that run on devices with limited input capabilities 
    (such as game consoles, video cameras, and printers) can access a 
    Compliant API on behalf of a user, but the user must have separate 
    access to a computer or device with richer input capabilities. 
    The flow is as follows:

    +---------+                                  +---------------+
    |         |                                  |               |
    |  Your   |>--(A)---- Request Code --------->| Authorization |
    |  App    |                                  |     Server    |
    |         |<--(B)-- URL & Auth Code --------<|               |
    |         |                                  |               |
    |         |        (seperate device)         |               |
    |         |>--(C)- User login & consent ---->|               |
    |         |                                  |               |
    |         |>--(D)---- Poll server ---------->|               |
    |         |                                  |               |
    |         |<--(D)-- Token response ---------<|               |
    |         |                                  |               |
    +---------+                                  +---------------+

                    Figure 1: Device OAUTH2 Flow

    The flow illustrated in Figure 1 includes the following steps:

    (A)  Your application begins this flow with a request to a Service URL
         with a set of parameters. The response includes a device code,
         a user code, a URL, an expiration, and a suggested polling
         interval.

    (B) After receipt of this response, your application shows the user
        the URL and the user code, and instructs the user to open a
        browser, navigate to the URL, and enter the code.

    (C) The user switches to a device or computer with richer input
        capabilities, launches a browser, navigates to the URL
        specified on the limited-input device, logs in, and enters
        the code.

    (D) In the background, your application polls a Service endpoint
        for an access token This token will only be returned to your
        application after the user has logged in and approved the request.
"""

import logging
import functools
from flask import request
from flask import _request_ctx_stack as stack
from werkzeug import cached_property
import datetime
import json
from ..utility import create_response, decode_base64, json_serial

log = logging.getLogger('flask_oauth2-devices')

class OAuth2DevicesProvider(object):
    """
    Provide secure services for devices using OAuth2.
    
    There are two usage modes. One is
    binding the Flask app instance::

        app = Flask(__name__)
        oauth = OAuth2DevicesProvider(app)

    The second possibility is to bind the Flask app later::
        oauth = OAuth2DevicesProvider()
        def create_app():
            app = Flask(__name__)
            oauth.init_app(app)
            return app
    """    

    def __init__(self, app=None):
        self._before_request_funcs = []
        self._after_request_funcs = []
        self._invalid_response = None
        if app:
            self.init_app(app)

    def init_app(self, app):
        """
        This callback can be used to initialize an application for the
        oauth2 provider instance.
        """
        self.app = app
        app.extensions = getattr(app, 'extensions', {})
        app.extensions['oauth2devices.provider.oauth2devices'] = self

    @cached_property
    def error_uri(self):
        """The error page URI.
        """
        error_uri = self.app.config.get('OAUTH2_DEVICES_PROVIDER_ERROR_URI')
        if error_uri:
            return error_uri
        error_endpoint = self.app.config.get('OAUTH2_DEVICES_PROVIDER_ERROR_ENDPOINT')
        if error_endpoint:
            return url_for(error_endpoint)
        return '/oauth/errors'

    def clientgetter(self, f):
        """Register a function as the client getter.
        The function accepts one parameter `client_id`, and it returns
        a client object with at least these information:
            - client_id: A random string
            - client_secret: A random string
            - client_type: A string represents if it is `confidential`
            - redirect_uris: A list of redirect uris
        Implement the client getter:
            @oauth.clientgetter
            def get_client(client_id):
                client = get_client_model(client_id)
                # Client is an object
                return client
        """
        self._clientgetter = f
        return f

    def authcodesetter(self, f):
        """Register a function to save the auth code.

        The setter accepts five parameters, a least
            - code: our auth_code, if none we will generate one
            - client_id: the client we want to create a new auth_code for
            - user_id: the user we want to create a new auth_code for
        Implement the auth_code setter:
            @oauth.authcodesetter
            def save_auth_code(code, client_id, user_id, *args, **kwargs)
                auth_code_model.save_code(code, client, user_id)
        """
        self._authcodesetter = f
        return f

    def authcodegetter(self, f):
        """ Register a function as the client getter.

        The function accepts one parameter `code`, and it returns
        a code object.
        Implement the auth code getter::
            @oauth.authcodegetter
            def load_auth_code(code):
                code = get_code_model(code)
                # Code is an object
                return code
        """
        self._authcodegetter = f
        return f

    def code_handler(self, authorize_link, activate_link, expires_interval, polling_internal):
        """ Code handler decorator

        The device requests an auth_code as part of (A)
        
        For example, the client makes the following HTTP request using
        transport-only security (with extra line breaks for display purposes
        only):

            POST /oauth/device HTTP/1.1
            Host: server.example.com
            Content-Type: application/x-www-form-urlencoded

        The authorization server MUST authenticate the client. 
        """

        def decorator(f):
            @functools.wraps(f)
            def wrapper(*args, **kwargs):
                ctx = stack.top
                if ctx is not None and hasattr(ctx, 'request'):
                    request = ctx.request
                    if request.method != 'POST':
                        log.warn('Attempted a non-post on the code_handler')
                        return create_response({'Allow': 'POST'}, 'must use POST', 405)

                    app = self.getApp(request)

                    if app is None:
                        raise OAuth2Exception(
                            'Invalid application credentials',
                            type='unauthorized_client'
                        )

                    auth_code = self._authcodesetter(None, app.client_id, app.user_id)
                    return self.create_oauth2_code_response(auth_code, authorize_link, activate_link, expires_interval, polling_internal)

                return f(*args, **kwargs)
            return wrapper
        return decorator

    def authorize_handler(self):
        """ Authorize handler decorator

        The device uses the auth_code and device code it recieved from (A)
        and attempts to exchange it for an access token.

        For example, the client makes the following HTTP request using
        transport-layer security (with extra line breaks for display
        purposes only):

            POST /oauth/device/authorize HTTP/1.1
            Host: server.example.com
            Content-Type: application/x-www-form-urlencoded

            {
                "auth_code": "656ea891"
                "device_code: "c8fe9de9e6c5f80bc543c492aaa2fbaf2b081601"
            }
        """

        def decorator(f):
            @functools.wraps(f)
            def wrapper(*args, **kwargs):
                ctx = stack.top
                if ctx is not None and hasattr(ctx, 'request'):
                    request = ctx.request
                    if request.method != 'POST':
                        log.warn('Attempted a non-post on the code_handler')
                        return create_response({'Allow': 'POST'}, 'must use POST', 405)

                    data = request.values
                    auth_code = self._authcodegetter(data.get('auth_code'))

                    if auth_code is None:
                        raise OAuth2Exception(
                            'This token could not be found',
                            type='invalid_token'
                        )

                    if auth_code.expires is None and auth_code.expires < datetime.utcnow():
                        raise OAuth2Exception(
                            'Authorization code has expired',
                            type='invalid_token'
                        )

                    device_code = data.get('device_code')

                    if auth_code.is_active == 0:
                        raise OAuth2Exception(
                            'You have not authorized this device code yet',
                            type='not_authorized'
                        )

                    if auth_code.get_device_code() != device_code:
                        raise OAuth2Exception(
                            'Your user code does not match the device',
                            type='invalid_token'
                        )

                    access_token = auth_code.exchange_for_access_token(auth_code)
                    return self.create_oauth2_token_response(access_token)

                return f(*args, **kwargs)
            return wrapper
        return decorator

    def create_oauth2_code_response(self, auth_code, authorize_link=None, activate_link=None, expires_interval=0, polling_interval=0):
        """
        The authorization server issues an device code which the device will have
        prompt the user to authorize before following the activate link to
        exchange for a access token. The following parameters are added to the
        entity-body of the HTTP response with a 200 (OK) status code:

        device_code
            REQUIRED.  The device code generated on the fly for each device.

        user_code
            REQUIRED.  The auth code issued by the authorization server.

        authorize_link
            REQUIRED.  The link where auth code can be exchanged for access 
                       token.

        activate_link
            REQUIRED.  The link where auth code can be activated via user
                       consent flow.

        expires_in
            RECOMMENDED.  The lifetime in seconds of the access token.  For
            example, the value "3600" denotes that the access token will
            expire in one hour from the time the response was generated.
            If omitted, the authorization server SHOULD provide the
            expiration time via other means or document the default value.

        interval
            REQUIRED. The recommended polling interval.

        For example:

            HTTP/1.1 200 OK
            Content-Type: application/json;charset=UTF-8
            Cache-Control: no-store
            Pragma: no-cache

            {
                "device_code": "73de035b2a7bdcb2c092f4bdfe292898e0657a18",
                "user_code": "656e6075",
                "authorize_link": "https://api.example.com/oauth/device/authorize",
                "activate_link": "https://example.com/activate",
                "expires_in": 3600,
                "interval": 15
            }
        """
        response = create_response({
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store',
            'Pragma': 'no-cache'}, json.dumps({
            'device_code' : auth_code.get_device_code(),
            'user_code ': auth_code.code,
            'authorize_link': authorize_link,
            'activate_link': activate_link,
            'expires_in': expires_interval,
            'interval': polling_interval}), 200)

        return response

    def create_oauth2_token_response(self, access_token):
        """
        The authorization server issues an access token and optional refresh
        token, and constructs the response by adding the following parameters
        to the entity-body of the HTTP response with a 200 (OK) status code:

        access_token
            REQUIRED.  The access token issued by the authorization server.

        token_type
            REQUIRED.  The type of the token issued as described in
            Section 7.1.  Value is case insensitive.

        expires_in
            RECOMMENDED.  The lifetime in seconds of the access token.  For
            example, the value "3600" denotes that the access token will
            expire in one hour from the time the response was generated.
            If omitted, the authorization server SHOULD provide the
            expiration time via other means or document the default value.

        refresh_token
            OPTIONAL.  The refresh token, which can be used to obtain new
            access tokens using the same authorization grant as described
            in Section 6.

        scope
            OPTIONAL, if identical to the scope requested by the client;
            otherwise, REQUIRED.  The scope of the access token as
            described by Section 3.3.

        The parameters are included in the entity-body of the HTTP response
        using the "application/json" media type as defined by [RFC4627].  The
        parameters are serialized into a JavaScript Object Notation (JSON)
        structure by adding each parameter at the highest structure level.
        Parameter names and string values are included as JSON strings.
        Numerical values are included as JSON numbers.  The order of
        parameters does not matter and can vary.

        The authorization server MUST include the HTTP "Cache-Control"
        response header field [RFC2616] with a value of "no-store" in any
        response containing tokens, credentials, or other sensitive
        information, as well as the "Pragma" response header field [RFC2616]
        with a value of "no-cache".

        For example:

            HTTP/1.1 200 OK
            Content-Type: application/json;charset=UTF-8
            Cache-Control: no-store
            Pragma: no-cache

            {
                "access_token":"2YotnFZFEjr1zCsicMWpAA",
                "token_type":"example",
                "scope":"public private",
                "expires_in":3600,
                "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA"
            }

        The client MUST ignore unrecognized value names in the response.  The
        sizes of tokens and other values received from the authorization
        server are left undefined.  The client should avoid making
        assumptions about value sizes.  The authorization server SHOULD
        document the size of any value it issues.

        http://tools.ietf.org/html/rfc6749#section-5.1
        """
        response = create_response({
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store',
            'Pragma': 'no-cache'}, json.dumps({
            'access_token' : access_token.access_token,
            'token_type ': access_token.token_type,
            'scope': access_token.scopes,
            'expires_in': json.dumps(access_token.expires, default=json_serial).replace("\"", ""),
            'refresh_token': None}), 200)

        return response

    def getApp(self, request):
        # http://tools.ietf.org/html/rfc2617#section-2

        client_id = None
        client_secret = None

        if "Authorization" in request.headers:
            auth_header = request.headers['Authorization']

            if "basic" in auth_header:
                auth = decode_base64(auth_header[6:]).split(':')
                client_id = auth[0]
                client_secret = auth[1]

        if client_id is None:
            raise OAuth2Exception(
                'A valid client ID must be provided along with request made',
                type='invalid_client'
            )

        app = self._clientgetter(client_id)

        if app is None:
            raise OAuth2Exception(
                'A valid client ID must be provided along with request made',
                type='invalid_client'
            )

        if client_secret is not None and client_secret == app.client_secret:
            return app

        raise OAuth2Exception(
            'A valid client secret must be provided along with request made',
            type='invalid_secret'
        )


class OAuth2Exception(RuntimeError):
    def __init__(self, message, type=None, data=None):
        self.message = message
        self.type = type
        self.data = data

    def __str__(self):
        return self.message.encode('utf-8')
