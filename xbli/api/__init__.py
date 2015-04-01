"""
The API which an xbox client communicates to
"""

from json import dumps
from os import urandom
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

from flask import make_response, current_app
from flask.ext.restful import Resource, Api, url_for

from xbli.api.commands import get_command_handler
from xbli.api.decorators import parse_request_data, check_user_agent, check_request_red_flags
from xbli.api.decorators import find_console, find_client_public_key
from xbli.api.utility import RequestParser, malicious_request_action, parse, local
from xbli.models import ApiLog, ConsolePublicKey
from xbli.api.utility.rsa import RSAKey


auth_parser = RequestParser()
auth_parser.add_argument('client_public_key', type=str, required=True)

api_parser = RequestParser()
api_parser.add_argument('command_code', type=int, required=True)


class AuthResource(Resource):
    """
    The auth resource handles setting up an encrypted channel to communicate through
    """

    method_decorators = [parse_request_data, check_user_agent, check_request_red_flags]

    def get(self):
        """
        This is the first contact from client -> server
        The server responds with its public key, which is used for further encryption
        """

        return current_app.rsa_key.public_data
    # we cannot expect the client to have a valid UA before knowing our public key
    get.check_ua = False
    get.check_data = False

    @parse(auth_parser)
    def post(self, data=None):
        """
        This is the second stage of the authentication
        The client sends all required authentication data to the server
        The request is encrypted with the servers public key

        The server responds with authentication status and user statistics
        The response is encrypted with the clients public key
        """

        # try to hex decode the public key data
        try:
            client_public_key_data = data.client_public_key.decode('hex')
        except TypeError:
            return malicious_request_action()

        # try to actually load the public key
        try:
            local.set_client_public_key(RSAKey(RSA.importKey(client_public_key_data)))
        except ValueError:
            return malicious_request_action()

        # store the public key for later use
        ConsolePublicKey.set(local.cpu_key, client_public_key_data)

        # log the auth
        ApiLog.log('auth')

        # get the api endpoint
        api_endpoint = url_for(ApiResource.endpoint)

        # construct a response
        response = dict(
            api_endpoint=api_endpoint
        )

        return response


class ApiResource(Resource):
    """
    The api resource handles all further communication between the client and server
    """

    method_decorators = [parse_request_data, find_console, find_client_public_key,
                         check_user_agent, check_request_red_flags]

    @parse(api_parser)
    def get(self, data=None):
        """
        This is where all api commands are routed through
        We must pull out the
        """

        # get the request code, defaulting to invalid request
        return get_command_handler(data.command_code)()


def output_infernuson(data, code, headers=None):
    """
    Causes all responses to be encrypted in 'infernuson' format
    """

    # dump the data to json if it is a dictionary
    if isinstance(data, dict):
        no_body = data.pop('no_body', False)
        if no_body:
            data = ''
        else:
            data = dumps(data)
    elif data is None:
        data = ''

    # add the header and the hash if data is encrypted
    if local.client_public_key and len(data):
        data = 'INF' + urandom(4) + local.client_public_key.aes_encrypt(data)
        data += SHA256.new(data).digest()

    # generate the response
    resp = make_response(data, code)
    resp.headers.extend(headers or {})

    return resp


class InfernusApi(Api):
    """
    Restful api customized for infernus
    """

    def __init__(self, *args, **kwargs):
        super(InfernusApi, self).__init__(*args, **kwargs)

        self.representations = {'application/infernuson': output_infernuson}
        self.default_mediatype = 'application/infernuson'
        self.add_resource(AuthResource, '/auth')
        self.add_resource(ApiResource, '/api')

    def unauthorized(self, response):
        """
        Overridden to prevent WWW-Authenticate header
        """

        return response
