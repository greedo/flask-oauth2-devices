**flask-oauth2-devices** is an extension to Flask that helps you to create the device flow for OAuth2 providers.
It is based on the implementation provided by `Google <https://developers.google.com/accounts/docs/OAuth2ForDevices>`__
and `Section 3.7 of the OAuth 2.05 specification <http://tools.ietf.org/html/draft-ietf-oauth-v2-05#section-3.7>`__.

Features
--------

- Support for OAuth2 device flow servers
- Friendly API (similar to flask-oauthlib)

More features may be added in the future just open an github `issue <https://github.com/greedo/flask-oauth2-devices/issues>`__
and add the enhancement label.

Installation
------------

The easiest way to install flask-oauth2-devices is with pip

::

    sudo pip install flask-oauth2-devices
    
Made sure your **sys.path** is correct.

Requirements
------------

- Python >= 2.7
- Flask >= 0.9

Testing
-------

To run the unit tests, you need pytest

::

    pip install pytest

Once you have that, ``cd`` into the root directory of this repo and

::

    py.test --tb=line -vs
    
Bugs
-------

For any bugs you encounter please open a github
`issue <https://github.com/greedo/flask-oauth2-devices/issues>`__ and add the bug label

License
-------

::

    The MIT License (MIT)

    Copyright (c) 2015 Joe Cabrera

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
