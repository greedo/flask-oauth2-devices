#! /usr/bin/env python
# encoding: utf-8

import six
import base64
import json
import pytest

from flask import Flask, make_response
from flask_sqlalchemy import SQLAlchemy
from flask.ext.wtf import Form
from wtforms import StringField, SelectField
from wtforms.validators import DataRequired
from devices import OAuth2DevicesProvider, OAuth2Exception
from utility import create_response

from datetime import datetime
import os
import sys
sys.path.insert(0, os.path.abspath('flask-oauth2-devices'))
try:
    del sys.path[sys.path.index('/home/joe/Projects/xbrl-plus')]
except:
    pass

oauth = OAuth2DevicesProvider()


def create_app():
    app = Flask(__name__)
    oauth.init_app(app)
    return app


@pytest.fixture
def app():
    app = create_app()
    return app


def test_get_code(client):
    res = make_response('http://127.0.0.1:5000/oauth/device', 200)
    res.headers['Authorization'] = 'basic MTIzNDU6MTIzNDU2Nzg5'
    assert ['device_code', 'user_code', 'authorize_link',
            'activate_link', 'expires_in', 'interval'] == res.json.keys()
