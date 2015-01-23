#! /usr/bin/env python
# encoding: utf-8

import six
import base64
import pytest
from datetime import datetime
from flask import request, Response
import os
import sys
sys.path.insert(0, os.path.abspath('flask-oauth2-devices'))

if six.PY3:
    bytes_type = bytes
else:
    bytes_type = str

from flaskoauth2devices import utility

def test_to_bytes(text):
    assert to_bytes("test") == "test"

def test_json_serial(obj):
    assert json.dumps(datetime.utcnow(), default=json_serial).replace("\"", "").replace("T", "") == str(datetime.datetime.utcnow())
