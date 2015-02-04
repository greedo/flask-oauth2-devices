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
