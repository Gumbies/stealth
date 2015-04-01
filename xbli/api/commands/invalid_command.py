from flask.ext.restful import abort
from xbli.models import ApiLog


def invalid_command():
    """
    Handles all command codes which are non existent with a 400 "Bad Request" response
    """

    ApiLog.log('invalid_command')
    return abort(400, no_body=True)
