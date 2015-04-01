from flask.ext.restful import wraps

from xbli.api.utility import client_not_authorized, local


def require_console_exists(func):
    """
    Requires the console exist in the database
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        # require the console to at least exist
        if not local.console:
            return client_not_authorized()

        # call the view function
        return func(*args, **kwargs)
    return wrapper
