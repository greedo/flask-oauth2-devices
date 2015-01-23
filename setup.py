try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup
import os

long_description = 'OAuth2 for devices flow implementation for Flask'
if os.path.exists('README.rst'):
    long_description = open('README.rst').read()

setup(
    name='flask-oauth2-devices',
    version='0.0.1',
    description='OAuth2 for devices flow implementation for Flask',
    author='Joe Cabrera',
    author_email='jcabrera@eminorlabs.com',
    url='https://github.com/greedo/flask-oauth2-devices',
    license='MIT License',
    keywords='Flask,    ',
    packages=[
        'devices',
        'devices.provider'],
    install_requires=[
        'pytest',
        'pep8',
        'Flask',
        'Flask-SQLAlchemy',
        'pyOpenSSL',
        'six'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Natural Language :: English',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: Implementation',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    long_description=long_description
)
