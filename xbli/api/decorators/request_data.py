import json
from Crypto.Hash import SHA256

from flask import request
from flask.ext.restful import wraps
from xbli.api.utility import malicious_request_action, bad_request_action, local


def parse_request_data(func):
    """
    Parse the encrypted JSON request body

    +--+--+--+-+-+-+-+================+-------------------+
    | Magic  | Nonce | Encrypted Data | SHA256 (32 bytes) |
    +--+--+--+-+-+-+-+================+-------------------+
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        # check for the skip flag on the view
        if not getattr(func, 'check_data', True):
            return func(*args, **kwargs)

        # check the magic header
        if not request.data.startswith('INF'):
            return malicious_request_action()

        # minimal size with hash and one byte data plus nonce
        if len(request.data) < 40:
            return malicious_request_action()

        # pull the request data apart
        sha = request.data[-32:]
        data = request.data[:-32]

        # check the sha256
        digest = SHA256.new(data).digest()
        if digest != sha:
            return bad_request_action()

        # separate the nonce and real data
        nonce = data[3:7]
        data = data[7:]
        if nonce == 0:
            return malicious_request_action()

        # decrypt data
        data = local.rsa_key.aes_decrypt(data)

        # decrypt and parse the json body
        local.set_data(json.loads(data))

        # call the view function
        return func(*args, **kwargs)
    return wrapper
