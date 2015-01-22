.. _oauth2:

OAuth2 Server
=============

An OAuth2 server concerns how to grant the authorization and how to protect
the resource. Register an **OAuth** provider::

    from flask_oauth2_devices.provider import OAuth2DevicesProvider

    app = Flask(__name__)
    oauth = OAuth2DevicesProvider(app)

Like any other Flask extensions, we can pass the application later::

    oauth = OAuth2DevicesProvider()

    def create_app():
        app = Flask(__name__)
        oauth.init_app(app)
        return app

To implement the authorization flow, we need to understand the data model.

Client (Application)
---------------------

A client is the app which want to use the resource of a user. It is suggested
that the client is registered by a user on your site, but it is not required.

The client should contain at least these properties:

- client_id: A random string
- client_secret: A random string
- client_type: A string represents if it is `confidential`
- redirect_uris: A list of redirect uris
- default_redirect_uri: One of the redirect uris
- default_scopes: Default scopes of the client

But it could be better, if you implemented:

- allowed_grant_types: A list of grant types
- allowed_response_types: A list of response types
- validate_scopes: A function to validate scopes

.. note::

    The value of the scope parameter is expressed as a list of space-
    delimited, case-sensitive strings.

    via: http://tools.ietf.org/html/rfc6749#section-3.3

An example of the data model in SQLAlchemy (SQLAlchemy is not required)::

    class Client(db.Model):
        client_id = db.Column(db.String(40), primary_key=True)
        client_secret = db.Column(db.String(55), nullable=False)

        user_id = db.Column(db.ForeignKey('user.id'))
        user = db.relationship('User')

        _redirect_uris = db.Column(db.Text)
        _default_scopes = db.Column(db.Text)

        @property
        def client_type(self):
            return 'public'

        @property
        def redirect_uris(self):
            if self._redirect_uris:
                return self._redirect_uris.split()
            return []

        @property
        def default_redirect_uri(self):
            return self.redirect_uris[0]

        @property
        def default_scopes(self):
            if self._default_scopes:
                return self._default_scopes.split()
            return []

