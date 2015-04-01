from flask import request
from flask.ext.restful import wraps
from xbli.api.utility import malicious_request_action


# headers which will cause a request to be considered malicious
BAD_HEADERS = set(('cookie', 'accept', 'accept-language', 'accept-encoding'))


def check_request_red_flags(func):
    """
    Checks the request for any common headers sent by web browsers and redirects the user away
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        headers = [key.lower() for key in request.headers.keys()]
        headers = BAD_HEADERS.intersection(headers)

        # check for any bad headers, errors here indicate an invalid request
        if len(headers):
            return malicious_request_action()

        # call the view function
        return func(*args, **kwargs)
    return wrapper
