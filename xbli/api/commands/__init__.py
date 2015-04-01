"""
Commands which the API implements
"""

__all__ = ['get_command_handler']


from xbli.api.commands.invalid_command import invalid_command
from xbli.api.commands.announce_command import announce_command
from xbli.api.commands.sendkv_command import sendkv_command
from xbli.api.commands.xekeysexecute_command import xekeysexecute_command
from xbli.api.commands.xosc_command import xosc_command


COMMAND_HANDLERS = {
    1: announce_command,
    2: sendkv_command,
    10: xekeysexecute_command,
    11: xosc_command
}


def get_command_handler(command_code):
    """
    Return the callable which handles the command specified by command_code
    defaults to invalid_command
    """
    return COMMAND_HANDLERS.get(command_code, invalid_command)
