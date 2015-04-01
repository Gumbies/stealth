from flask.ext.restful import wraps
from xbli.api.utility import client_needs_authentication, local
from xbli.models import ConsolePublicKey, Console


def find_client_public_key(func):
    """
    Uses the cpu key from the user agent to locate the public key for the client
    If not found, tell the user to reauthenticate
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        # locate the public key
        local.set_client_public_key(ConsolePublicKey.get(local.cpu_key))

        # if not found, abort the request
        if not local.client_public_key:
            return client_needs_authentication()

        # call the view function
        return func(*args, **kwargs)
    return wrapper


def find_console(func):
    """
    Uses the cpu key from the user agent to locate the console for the client
    This does not fail when no console is found
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        # locate the public key
        local.set_console(Console.get(local.cpu_key))

        # call the view function
        return func(*args, **kwargs)
    return wrapper
