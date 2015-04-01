import inspect

from flask import redirect, current_app
from flask.ext.restful import abort, wraps, reqparse
from xbli.models import ApiLog
from xbli.api.utility import local


class Argument(reqparse.Argument):
    """
    Wrapped to pull all data from the decrypted json object
    """

    def handle_validation_error(self, error):
        msg = self.help if self.help is not None else str(error)
        ApiLog.log('bad_request', msg)
        abort(400, message=msg)

    def source(self, request):
        return local.data


class RequestParser(reqparse.RequestParser):
    def __init__(self, argument_class=Argument, namespace_class=reqparse.Namespace):
        self.args = []
        self.argument_class = argument_class
        self.namespace_class = namespace_class


def parse(parser):
    """
    Uses a RequestParser to require a specific body schema
    """

    def outer_wrapper(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # run the parser
            kwargs['data'] = parser.parse_args()

            # call the view function
            return func(*args, **kwargs)
        return wrapper
    return outer_wrapper


def malicious_request_action():
    """
    Action to take when a request is considered maliciously malformed
    """

    # get the caller info
    frame, filename, line_number, function_name, lines, index = inspect.getouterframes(inspect.currentframe())[1]

    # log the location of request failure
    ApiLog.log('malicious_request', '{0}: {1}@{2}'.format(filename, function_name, line_number))

    if current_app.debug:
        raise Exception()
    else:
        return redirect('http://lmgtfy.com/?q=how+do+I+mind+my+own+fucking+business%3F')


def bad_request_action():
    """
    Action to take when a request is malformed, but not considered malicious
    """

    # get the caller info
    frame, filename, line_number, function_name, lines, index = inspect.getouterframes(inspect.currentframe())[1]

    # log the location of request failure
    ApiLog.log('bad_request', '{0}: {1}@{2}'.format(filename, function_name, line_number))

    return abort(400)


def client_needs_authentication():
    """
    The client needs to reauthenticate themselves
    """

    ApiLog.log('needs_authentication')
    return abort(401, no_body=True)


def client_not_authorized():
    """
    The client is not authorized to use this command
    """

    ApiLog.log('not_authorized')
    return abort(403, no_body=True)
