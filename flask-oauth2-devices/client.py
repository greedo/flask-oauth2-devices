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

from functools import wraps
from flask import request, redirect
import requests
import urllib3
import datetime
import pyOpenSSL
import hashlib

class OAuth2devices(object):

    def code(self, callback=None, state=None, **kwargs):
        """
        The device requests an auth_code as part of (A)
        
        For example, the client makes the following HTTP request using
        transport-only security (with extra line breaks for display purposes
        only):

            POST /oauth/device HTTP/1.1
            Host: server.example.com
            Content-Type: application/x-www-form-urlencoded

        The authorization server MUST authenticate the client. 
        """

        if self.request.method is "POST":
            self.request.headers = {'Allow': 'POST'}
            self.request.status_code = 405

        if getApp() is None:
            raise OAuth2Exception(
                'Invalid application credentials',
                type='unauthorized_client'
            )

        scope = self.request.json()['scope']
        auth_code = AuthorizationCode(app_id, user_id, scope, expires_one)
        auth_code.create_new_code()

        return create_oauth2_code_response(authorize_link, activate_link, expires_interval, polling_interval)

    def authorize(self, callback=None, state=None, **kwargs):
        """
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

        if self.request.method is "POST":
            self.request.headers = {'Allow': 'POST'}
            self.request.status_code = 405

        data = requests.json()
        auth_code = AuthorizationCode().load(data['auth_code'])

        if auth_code is None:
            raise OAuth2Exception(
                'This token could not be found',
                type='invalid_token'
            )

        if auth_code.expires_on is None and auth_code.expires_on < datetime.datetime.now():
            raise OAuth2Exception(
                'Authorization code has expired',
                type='invalid_token'
            )

        device_code = data['device_code']

        if auth_code.device_code is False:
            raise OAuth2Exception(
                'You have not authorized this device code yet',
                type='not_authorized'
            )

        if auth_code.get_device_code() != device_code:
            raise OAuth2Exception(
                'Your auth code does not match the device',
                type='invalid_token'
            )

        access_token = auth_code.exchange_for_access_token()

        return create_oauth2_code_response(authorize_link, activate_link, expires_interval, polling_interval)

    def create_oauth2_code_response(authorize_link=None, activate_link=None, expires_interval=0, polling_interval=0):
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
        self.response = urllib3.response.HTTPResponse({
            'device_code' : auth_code.get_device_code(),
            'authorize_code ': auth_code.code,
            'authorize_link': authorize_link,
            'activate_link': activate_link,
            'expires_in': expires_interval,
            'interval': polling_interval}, {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store',
            'Pragma': 'no-cache'}

        return self.response

    def create_oauth2_token_response(access_token=None):
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
                "expires_in":3600,
                "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
                "example_parameter":"example_value"
            }

        The client MUST ignore unrecognized value names in the response.  The
        sizes of tokens and other values received from the authorization
        server are left undefined.  The client should avoid making
        assumptions about value sizes.  The authorization server SHOULD
        document the size of any value it issues.

        http://tools.ietf.org/html/rfc6749#section-5.1
        """
        self.response = urllib3.response.HTTPResponse({
            'access_token' : access_token,
            'token_type ': access_token.token_type,
            'scope': authorize_link,
            'expires_in': expires_interval,
            'refresh_token': polling_interval}, {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store',
            'Pragma': 'no-cache'}

        return self.response

    def getApp():
        # http://tools.ietf.org/html/rfc2617#section-2
        if self.request.headers['Authorization'] is not None:   
            auth_header = self.request.headers['Authorization']

            if "basic" in auth_header:
                auth = decode_base64(auth_header[6:]).split(':')
                client_id = auth[0]
                client_secret = auth[1]

            if client_id is None:
                raise OAuth2Exception(
                    'A valid client ID must be provided along with request made',
                    type='invalid_client'
                )

            if client_secret is None:
                raise OAuth2Exception(
                    'A valid client secret must be provided along with request made',
                    type='invalid_secret'
                )

class AccessToken():
    """
    +--------+                                           +---------------+
    |        |--(A)------- Authorization Grant --------->|               |
    |        |                                           |               |
    |        |<-(B)----------- Access Token -------------|               |
    |        |               & Refresh Token             |               |
    |        |                                           |               |
    |        |                            +----------+   |               |
    |        |--(C)---- Access Token ---->|          |   |               |
    |        |                            |          |   |               |
    |        |<-(D)- Protected Resource --| Resource |   | Authorization |
    | Client |                            |  Server  |   |     Server    |
    |        |--(E)---- Access Token ---->|          |   |               |
    |        |                            |          |   |               |
    |        |<-(F)- Invalid Token Error -|          |   |               |
    |        |                            +----------+   |               |
    |        |                                           |               |
    |        |--(G)----------- Refresh Token ----------->|               |
    |        |                                           |               |
    |        |<-(H)----------- Access Token -------------|               |
    +--------+           & Optional Refresh Token        +---------------+


    The flow illustrated in Figure 2 includes the following steps:

     (A)  The client requests an access token by authenticating with the
          authorization server, and presenting an authorization grant.
     (B)  The authorization server authenticates the client and validates
          the authorization grant, and if valid issues an access token and
          a refresh token.
     (C)  The client makes a protected resource request to the resource
          server by presenting the access token.
     (D)  The resource server validates the access token, and if valid,
          serves the request.
     (E)  Steps (C) and (D) repeat until the access token expires.  If the
          client knows the access token expired, it skips to step (G),
          otherwise it makes another protected resource request.
     (F)  Since the access token is invalid, the resource server returns
          an invalid token error.
     (G)  The client requests a new access token by authenticating with
          the authorization server and presenting the refresh token.  The
          client authentication requirements are based on the client type
          and on the authorization server policies.
     (H)  The authorization server authenticates the client and validates
          the refresh token, and if valid issues a new access token (and
          optionally, a new refresh token).

    Steps C, D, E, and F are outside the scope of this specification
    This access token is granted as a Bearer token, as defined by http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-22
    """
    def __init__(app_id=0, user_id=0, scope=None, expires_on=None):
        self.app_id = app_id
        self.user_id = user_id
        self.scope = scope
        self.expires_on = expires_on

    def refresh(token):
        token = AccessToken()
        token.user_id = self.user_id
        token.app_id = self.app_id
        token.grant_type = self.grant_type
        token.token_type = self.token_type
        token.refresh_token = create_new_refresh_token()

    def create_new_token():
        return hashlib.md5("app:" + self.app_id + ":user:" + self.user_id + ":" + pyOpenSSL.rand())

    def create_new_refresh_token():
        return hashlib.sha1("app:" + self.app_id + ":user:" + ":token:" + self.id)


class AuthorizationCode():

    __is_active = False

    OUR_KEY = "ourbigbadkey"
    AUTH_EXPIRATION_TIME = 600

    def __init__(app_id=0, user_id=0, scope=None, expires_on=None):
        self.app_id = app_id
        self.user_id = user_id
        self.scope = scope
        self.expires_on = expires_on

    def exchange_for_access_token():
        access_token = 

    def get_device_code():
        return hmac.new(OUR_KEY, 'secret:'.self.id, 'sha1')

    def create_new_code():
        self.code = hashlib.sha1("secret:" + self.app_id + ":req:" + pyOpenSSL.rand())
        __is_active = True
        self.created = datetime.datetime.now().date()

        if self.expires_on is None:
            self.expires_on = datetime.datetime.now().date() + AUTH_EXPIRATION_TIME


class OAuth2Exception(RuntimeError):
    def __init__(self, message, type=None, data=None):
        self.message = message
        self.type = type
        self.data = data

    def __str__(self):
        return self.message.encode('utf-8')
