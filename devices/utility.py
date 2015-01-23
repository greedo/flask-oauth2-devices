import six
import base64
from datetime import datetime
from flask import request, Response

if six.PY3:
    unicode_type = str
    bytes_type = bytes
else:
    unicode_type = unicode
    bytes_type = str

def to_unicode(data):
    """Convert utf-8 to unicode."""
    if isinstance(data, bytes_type):
        return unicode_type(data, 'UTF-8')

    if hasattr(data, '__iter__'):
        try:
            dict(data)
        except TypeError:
            pass
        except ValueError:
            return (to_unicode(i, 'UTF-8') for i in data)
        else:
            if hasattr(data, 'items'):
                data = data.items()
            return dict(((to_unicode(k, 'UTF-8'), to_unicode(v, 'UTF-8')) for k, v in data))

    return data

def to_bytes(text):
    """Make sure text is bytes type."""
    if not text:
        return text
    if not isinstance(text, bytes_type):
        text = text.encode('utf-8')
    return text

def decode_base64(text):
    """Decode base64 string from utf-8."""
    text = to_bytes(text)
    return to_unicode(base64.b64decode(text))

def create_response(headers, body, status):
    """Create response object for Flask."""
    response = Response(body or '')
    for k, v in headers.items():
        response.headers[str(k)] = v

    response.status_code = status
    return response

def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, datetime):
        serial = obj.isoformat()
        return serial
