#! /usr/bin/env python
# encoding: utf-8

import six
import base64

from flask import Flask, make_response
from flask_sqlalchemy import SQLAlchemy
from flask.ext.wtf import Form
from flask.ext.testing import TestCase
from flask.ext.fixtures import Fixtures
from wtforms import StringField, SelectField
from wtforms.validators import DataRequired
from devices import OAuth2DevicesProvider, OAuth2Exception
from utility import create_response
from myservice import app, db
from urllib import urlencode
from myservice import Client, User, Token

from datetime import datetime
import os
import sys
sys.path.insert(0, os.path.abspath('flask-oauth2-devices'))
try:
    del sys.path[sys.path.index('/home/joe/Projects/xbrl-plus')]
except:
    pass

oauth = OAuth2DevicesProvider()
fixtures = Fixtures(app, db)

# recreate all the oauth2_models
db.drop_all()
db.create_all()

@fixtures('/home/joe/Projects/flask-oauth2-devices/tests/fixtures/oauth2_models.json')
class TestViews(TestCase):

    def create_app(self):
        self.token = base64.b64encode('12345:123456789')
        return app

    def test_get_device_code(self):
        """Getting device code for a new unauthenticated device"""

        response = self.client.get("/oauth/device")
        self.assert405(response)

    def test_post_device_code(self):
        """Posting device code for a new unauthenticated device"""

        response = self.client.post("/oauth/device", headers={'Authorization': 'basic ' + self.token})
        self.assert200(response)

    def test_get_device_code(self):
        """Authorize a new device"""

        response = self.client.post("/oauth/device/authorize", headers={'Authorization': 'basic ' + self.token})
        self.assert401(response)
