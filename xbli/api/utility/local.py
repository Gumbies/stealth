from werkzeug.local import LocalProxy
from flask import g

__all__ = ['client_public_key', 'cpu_key', 'console', 'data', 'rsa_key',
           'set_client_public_key', 'set_cpu_key', 'set_console', 'set_data', 'set_rsa_key']


client_public_key = LocalProxy(lambda: g.get('client_public_key', None))
cpu_key = LocalProxy(lambda: g.get('cpu_key', None))
console = LocalProxy(lambda: g.get('console', None))
data = LocalProxy(lambda: g.get('data', None))
rsa_key = LocalProxy(lambda: g.get('rsa_key', None))


def set_client_public_key(value):
    g.client_public_key = value


def set_cpu_key(value):
    g.cpu_key = value


def set_console(value):
    g.console = value


def set_data(value):
    g.data = value


def set_rsa_key(value):
    g.rsa_key = value
