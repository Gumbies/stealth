from base64 import b64decode
from binascii import crc32
import struct

from flask import request, current_app
from flask.ext.restful import abort, wraps
from xbli.api.utility import malicious_request_action, bad_request_action, local
from xbli.utility import cpukey


def check_user_agent(func):
    """
    Checks the validity of the user agent header

    The header should be RSA encrypted, then base64 encoded
    The format (decrypted) is as follows:
        +------+------+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | magic bytes | CPU Key (16 bytes)            | Nonce |
        +------+------+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        magic bytes = 'UA'

    Once RSA encrypted, the format is as follows:
        +------+------+====================+
        | magic bytes | RSA Encrypted Data |
        +------+------+====================+
        magic bytes = 'UA'

    This data is then base64 encoded
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        # check for the skip flag on the view
        if not getattr(func, 'check_ua', True):
            return func(*args, **kwargs)

        # get the user agent from headers, errors here indicate an invalid request
        user_agent = request.headers.get('User-Agent', None)
        if user_agent is None:
            return malicious_request_action()

        # base64 decode the user agent, errors here indicate an invalid request
        try:
            user_agent = b64decode(user_agent)
        except TypeError:
            return malicious_request_action()

        # check the encrypted user agent length, errors here indicate an invalid request
        if len(user_agent) != 262:
            return malicious_request_action()

        # check the magic bytes before decryption, errors here indicate an invalid request
        if not user_agent.startswith('UA'):
            return malicious_request_action()

        # calculate and verify crc of data
        crc = struct.pack('<L', crc32(user_agent[:-4]) & 0xFFFFFFFF)
        if crc != user_agent[-4:]:
            return bad_request_action()

        # decrypt the user agent data with the current applications RSA key
        try:
            user_agent = current_app.rsa_key.decrypt(user_agent[2:-4])
        except ValueError:
            # decryption failed, indicate a reauth is required
            return abort(401, no_body=True)

        # check the magic bytes after decryption, errors here indicate correct decryption, but invalid request
        if not user_agent.startswith('UA'):
            return malicious_request_action()

        # check the user agent length, errors here indicate an invalid request
        if len(user_agent) != struct.calcsize('2x 16s 4x'):
            return malicious_request_action()

        # pull the cpu key from the user agent
        cpu_key = struct.unpack('2x 16s 4x', user_agent)[0]

        # check the validity of the cpu key
        if not cpukey.is_valid(cpu_key):
            return malicious_request_action()

        # hex encode for convenience
        local.set_cpu_key(cpu_key.encode('hex'))

        # call the view function
        return func(*args, **kwargs)
    return wrapper
