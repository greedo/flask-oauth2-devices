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
            headers = {'Allow': 'POST'}
            self.request.status_code = 405

        if getApp() is None:
            raise OAuth2Exception(
                'Invalid application credentials',
                type='unauthorized_client'
            )

        scope = self.request.json()['scope']
        auth_code = createAuthCode( scope

        self.response = urllib3.response.HTTPResponse({
            'device_code' : auth_code.getDeviceCode(),
            'authorize_code ': auth_code.code,
            'authorize_link': kwargs['authorize_link'],
            'activate_link': kwargs['activate_link'],
            'expires_in': kwargs['expires_interval'],
            'interval': kwargs['polling_interval']})
        return self.response

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
        params = dict(self.request_token_params) or {}
        params.update(**kwargs)


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


class OAuth2Exception(RuntimeError):
    def __init__(self, message, type=None, data=None):
        self.message = message
        self.type = type
        self.data = data

    def __str__(self):
        return self.message.encode('utf-8')
