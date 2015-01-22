import OpenSSL
import hmac
import hashlib
from binascii import hexlify
from datetime import datetime, timedelta
from flask import Flask, abort, render_template, make_response, request
from flask_sqlalchemy import SQLAlchemy
from flask.ext.wtf import Form
from wtforms import StringField, SelectField
from wtforms.validators import DataRequired
from oauth2devices import OAuth2DevicesProvider, OAuth2Exception

from forms import ActivateForm

app = Flask(__name__)
app.config.update(
    WTF_CSRF_ENABLED = True,
    SECRET_KEY = 'our-big-bad-key'
)
app.config.update({
    'SQLALCHEMY_DATABASE_URI': 'sqlite:///db.sqlite'
})
db = SQLAlchemy(app)
oauth = OAuth2DevicesProvider(app)

AUTH_EXPIRATION_TIME = 3600
OUR_KEY = 'our-big-bad-key'

@app.route('/oauth/device', methods=['POST'])
@oauth.code_handler("https://api.example.com/oauth/device/authorize", "https://example.com/activate", 600, 600)
def code():
    return None

@app.route('/oauth/device/authorize', methods=['POST'])
@oauth.authorize_handler()
def authorize():
    return None

@app.route('/activate', methods=['GET', 'POST'])
def activate_view():

    form = ActivateForm()
    if form.validate_on_submit():
        if request.method == "POST":

            user_code = load_auth_code(request.values.get('user_code'))

            if user_code is None or user_code.expires < datetime.utcnow():
                return render_template('app_auth_error.html')

            return redirect("/oauth/authorization/accept?user_code="+str(user_code.code))

    resp = make_response(render_template('user_code_activate.html', form=form))
    resp.headers.extend({'X-Frame-Options': 'DENY'})
    return resp

@app.route('/oauth/authorization/accept', methods=['GET', 'POST'])
def authorization_accept_view():

    user_code = load_auth_code(request.values.get('user_code'))

    all_scopes = ['private']

    # public is our default scope in this case
    if request.values.get('scopes') is None:
        scopes = ['public']
    else:
        scopes = request.values.get('scopes').split()

    non_scopes = [scope for scope in all_scopes if scope not in scopes]

    resp = make_response(render_template('access_token_authorize.html',
                                         app_id=user_code.client_id,
                                         client_id=user_code.client_id,
                                         user_code=user_code.code,
                                         scopes=scopes,
                                         non_scopes=non_scopes))
    resp.headers.extend({'X-Frame-Options': 'DENY'})
    return resp

@app.route('/confirmed', methods=['POST'])
def confirmed_view():

    # just an extra check in case we didn't block GET in the decorator
    if request.method != "POST":
        resp = make_response("non-POST on access token", 405)
        resp.headers.extend({'Allow': 'POST'})
        return resp

    client_id = request.values.get('client_id')

    if client_id is None:
        return make_response("missing client_id", 500)

    # we can load our app by client_id here 
    # and throw a 500 if we have a problem

    user_code = load_auth_code(request.values.get('user_code'))

    if user_code is None:
        return make_response("auth code must be sent", 400)

    user_code.is_active = 1
    db.session.commit()

    resp = make_response(render_template('app_auth_confirm.html', client_id=user_code.client_id))
    resp.headers.extend({'X-Frame-Options': 'DENY'})
    return resp

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True)

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

class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(
        db.String(40), db.ForeignKey('client.client_id'),
        nullable=False,
    )
    client = db.relationship('Client')

    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id')
    )
    user = db.relationship('User')

    # currently only bearer is supported
    token_type = db.Column(db.String(40))

    access_token = db.Column(db.String(255))
    refresh_token = db.Column(db.String(255))
    expires = db.Column(db.DateTime)
    created = db.Column(db.DateTime)
    _scopes = db.Column(db.Text)

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []

    def create_access_token(self, client_id, user_id, scope, token_type):

        expires_in = AUTH_EXPIRATION_TIME
        expires = datetime.utcnow() + timedelta(seconds=expires_in)
        created = datetime.utcnow()

        tok = Token(
            client_id=client_id,
            user_id=user_id,
            access_token=None,
            refresh_token=None,
            token_type=token_type,
            _scopes = ("public private" if scope is None else ' '.join(scope)),
            expires=expires,
            created=created,
        )

        if tok.access_token is None:
            tok.access_token = tok._generate_token()

        db.session.add(tok)
        db.session.commit()
        return tok

    def refresh(self, token):

        tok = Token(
            client_id=self.client_id,
            user_id=self.user_id,
            access_token=self.access_token,
            refresh_token=None,
            token_type=token_type,
            _scopes = ("public private" if scope is None else ' '.join(scope)),
            expires=expires,
            created=created,
        )

        if tok.refresh_token is None:
            tok.refresh_token = tok._generate_refresh_token()

        db.session.add(tok)
        db.session.commit()
        return tok

    def _generate_token(self):
        return hashlib.sha1("app:" + str(self.client_id) + ":user:" + str(self.user_id) + str(hexlify(OpenSSL.rand.bytes(10)))).hexdigest()

    def _generate_refresh_token(self):
        return hashlib.sha1("app:" + str(self.client_id) + ":user:" + str(self.user_id) + ":access_token:" + str(self.id)).hexdigest()

    def contains_scope(scope):
        return scope in self.scope.split(' ')

class Code(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(
        db.String(40), db.ForeignKey('client.client_id'),
        nullable=False,
    )
    client = db.relationship('Client')

    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id')
    )
    user = db.relationship('User')

    code = db.Column(db.String(40), unique=True)
    _scopes = db.Column(db.Text)
    expires = db.Column(db.DateTime)
    created = db.Column(db.DateTime)
    is_active = db.Column(db.Integer)

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []

    def generate_new_code(self, client_id):
        return hashlib.sha1("secret:" + client_id + ":req:" + str(hexlify(OpenSSL.rand.bytes(10)))).hexdigest()

    def get_device_code(self):
        return hmac.new(OUR_KEY, "secret:"+str(self.id), hashlib.sha1).hexdigest()

    def exchange_for_access_token(self, app):
        return Token().create_access_token(app.client_id, app.user_id, app.scopes, "grant_auth_code")

def current_user():
    if 'id' in session:
        uid = session['id']
        return User.query.get(uid)
    if 'id' in request.args:
        return User.query.get(request.args.get('id'))
    return None

@oauth.clientgetter
def load_client(client_id):
    return Client.query.filter_by(client_id=client_id).first()

@oauth.authcodesetter
def save_auth_code(code, client_id, user_id, *args, **kwargs):
    codes = Code.query.filter_by(
        client_id=client_id,
        user_id=user_id
    )

    # make sure that every client has only one code connected to a user
    for c in codes:
        db.session.delete(c)

    expires_in = (AUTH_EXPIRATION_TIME if code is None else code.pop('expires_in'))
    expires = datetime.utcnow() + timedelta(seconds=expires_in)
    created = datetime.utcnow()

    cod = Code(
        client_id=client_id,
        user_id=user_id,
        code = (None if code is None else code['code']),
        _scopes = ('public private' if code is None else code['scope']),
        expires=expires,
        created=created,
        is_active=0
    )

    if cod.code is None:
        cod.code = cod.generate_new_code(cod.client_id)[:8]

    db.session.add(cod)
    db.session.commit()
    return cod

@oauth.authcodegetter
def load_auth_code(code):
    return Code.query.filter_by(code=code).first()

if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)
