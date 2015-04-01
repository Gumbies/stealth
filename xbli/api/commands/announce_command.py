from xbli.models import ApiLog, KeyVault, Console
from xbli.api.utility import RequestParser, parse, bad_request_action, local


announce_parser = RequestParser()
announce_parser.add_argument('kv_hash', type=str, required=True)
announce_parser.add_argument('fake_cpu', type=str, required=True)


@parse(announce_parser)
def announce_command(data=None):
    """
    Handles console announce
    """

    ApiLog.log('announce_command')

    # check the hash length
    if len(data.kv_hash) != 32:
        return bad_request_action()

    # TODO: not do this
    # create the console implicitly
    if not local.console:
        local.set_console(Console(cpu_key=local.cpu_key))
        local.console.save()

    # note the console login
    local.console.login_from_request()

    # lookup the kv by hash
    kv = KeyVault.get(data.kv_hash)
    send_kv = not kv

    # if kv already exists, mark usage
    if not send_kv:
        local.console.use_kv_from_request(kv)

    return dict(send_kv=send_kv)
