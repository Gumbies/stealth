from mongoengine.errors import NotUniqueError
from xbli.models import ApiLog, KeyVault
from xbli.api.utility import RequestParser, parse, bad_request_action, local


sendkv_parser = RequestParser()
sendkv_parser.add_argument('blob', type=str, required=True)
sendkv_parser.add_argument('fake_cpu', type=str, required=True)


@parse(sendkv_parser)
def sendkv_command(data=None):
    """
    Handles the console sending a keyvault
    """

    ApiLog.log('sendkv_command')

    # check blob length
    if len(data.blob) != 0x8000 or len(data.fake_cpu) != 32:
        return bad_request_action()

    # try decoding the required parameters
    try:
        blob = data.blob.decode('hex')
        cpu_key = data.fake_cpu.decode('hex')
    except UnicodeDecodeError:
        return bad_request_action()

    # create the key vault
    try:
        kv = KeyVault.create(blob, cpu_key)
        local.console.use_kv_from_request(kv)
    except NotUniqueError:
        return bad_request_action()

    return dict(cpu_key_verified=kv.cpu_key_verified)
