from xbli.models import ApiLog
from xbli.api.utility import RequestParser, parse, bad_request_action, local
from xbli.api.utility.xekeysexecute import calculate_from_keyvault


xekeysexecute_parser = RequestParser()
xekeysexecute_parser.add_argument('salt', type=str, required=True)
xekeysexecute_parser.add_argument('crl', type=bool, required=True)
xekeysexecute_parser.add_argument('physical_address', type=int, required=True)


@parse(xekeysexecute_parser)
def xekeysexecute_command(data=None):
    """
    Handles XeKeysExecute payload generation
    """

    ApiLog.log('xekeysexecute_command')

    # check salt length
    if len(data.salt) != 32:
        return bad_request_action()

    # decode the salt
    try:
        salt = data.salt.decode('hex')
    except UnicodeDecodeError:
        return bad_request_action()

    # calculate and encode the response
    blob = calculate_from_keyvault(local.console.current_key_vault, salt, data.crl).encode('hex')
    return dict(blob=blob)
