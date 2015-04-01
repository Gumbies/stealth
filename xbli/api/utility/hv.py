from hashlib import sha1

from flask import current_app
from xbli.utility import read_count


def get_hv():
    return current_app.fs.get_last_version('HV.bin').read()


def calculate_hv_hash(salt):
    """
    given a salt value, generate the hash for the hypervisor
    """

    hv = get_hv()
    hvhash = sha1(salt[:16])
    hvhash.update(read_count(hv, 0x34, 0x40))
    hvhash.update(read_count(hv, 0x78, 0xF88))
    hvhash.update(read_count(hv, 0x100C0, 0x40))
    hvhash.update(read_count(hv, 0x10350, 0xDF0))
    hvhash.update(read_count(hv, 0x16D20, 0x2E0))
    hvhash.update(read_count(hv, 0x20000, 0xFFC))
    hvhash.update(read_count(hv, 0x30000, 0xFFC))

    return hvhash.digest()[14:20]
