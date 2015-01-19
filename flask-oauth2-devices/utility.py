from flask import request, Response

def decode_base64(text, encoding='utf-8'):
    """Decode base64 string."""
    text = to_bytes(text, encoding)
    return to_unicode(base64.b64decode(text), encoding)

def create_response(headers, body, status):
    """Create response class for Flask."""
    response = Response(body or '')
    for k, v in headers.items():
        response.headers[str(k)] = v

    response.status_code = status
    return response
