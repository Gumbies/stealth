from xbli.models import ApiLog
from xbli.api.utility import RequestParser, parse, bad_request_action, local
from xbli.api.utility.xosc import calculate_from_keyvault


xosc_parser = RequestParser()
xosc_parser.add_argument('crl', type=bool, required=True)
xosc_parser.add_argument('term_pend', type=bool, required=True)
xosc_parser.add_argument('should_exit', type=bool, required=True)
xosc_parser.add_argument('hv_pflags', type=int, required=True)
xosc_parser.add_argument('exec_id_res', type=int, required=True)
xosc_parser.add_argument('exec_id', type=str)
xosc_parser.add_argument('part_sizes', type=str, required=True)


@parse(xosc_parser)
def xosc_command(data=None):
    """
    Handles XOSC payload generation
    """

    ApiLog.log('xosc_command')

    exec_id = getattr(data, 'exec_id', '')
    part_sizes = data.part_sizes

    # part sizes must be the correct length
    if len(part_sizes) != 56:
        return bad_request_action()

    # check exec id consistency
    if data.exec_id_res >= 0:
        # exec id must exist and be correct length
        if len(exec_id) != 48:
            return bad_request_action()

        # exec id must hex decode properly
        try:
            exec_id = exec_id.decode('hex')
        except UnicodeDecodeError:
            return bad_request_action()

    # part sizes must hex decode properly
    try:
        part_sizes = part_sizes.decode('hex')
    except UnicodeDecodeError:
        return bad_request_action()

    # calculate the blob response
    blob = calculate_from_keyvault(local.console.current_key_vault, data.hv_pflags, data.crl, data.term_pend,
                                   data.should_exit, data.exec_id_res, exec_id, part_sizes)

    return dict(blob=blob.encode('hex'))
