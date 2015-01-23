#! /usr/bin/env python
# encoding: utf-8

import six
import base64
import json
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

from utility import create_response, decode_base64, to_bytes, json_serial


def test_to_bytes():
    assert to_bytes("test") == "test"


def test_json_serial():
    assert json.dumps(datetime.utcnow(),
                      default=json_serial).replace("\"", "").replace("T", "").split(".")[0] == \
        str(datetime.utcnow()).split(".")[0].replace(" ", "")
