import hashlib
import struct
import random

from xbli.api.utility.hv import calculate_hv_hash


# constants
HV_MAGIC = 0x4E4E
HV_VERSION = 0x40A3
HV_QFE = 0x0000
HVEX_ADDR = 0x01B7
BASE_KERNEL_VERSION = 0x07600000
UPDATE_SEQUENCE = 0x00000006
RTOC = 0x0000000200000000
HRMOR = 0x0000010000000000

# variables
HV_KEYS_STATUS_FLAGS = 0x023289D3
HV_KEYS_STATUS_FLAGS_CRL = 0x10000
HV_KEYS_STATUS_FLAGS_FCRT = 0x1000000
BLDR_FLAGS = 0xD83E
BLDR_FLAGS_KV1 = (~0x20)
CTYPE_SEQ_ALLOW_KV1 = 0x010B0400
CTYPE_SEQ_ALLOW_KV2 = 0x0304000D


def calculate_from_keyvault(kv, salt, crl):
    """
    calculate the xekeys response from the given kv and salt
    """

    # create an empty blob of 0x100 bytes
    blob = bytearray(0x100)

    # store some constants into the blob
    struct.pack_into('>H', blob, 0x28, HV_MAGIC)
    struct.pack_into('>H', blob, 0x2A, HV_VERSION)
    struct.pack_into('>H', blob, 0x2C, HV_QFE)
    struct.pack_into('>L', blob, 0x30, BASE_KERNEL_VERSION)
    struct.pack_into('>L', blob, 0x34, UPDATE_SEQUENCE)
    struct.pack_into('>Q', blob, 0x40, RTOC)
    struct.pack_into('>Q', blob, 0x48, HRMOR)
    struct.pack_into('>H', blob, 0xF8, HVEX_ADDR)

    # generate random ecc hash
    ecchash = hashlib.sha1(str(random.getrandbits(16 * 8))).hexdigest()[:20]

    # generate cpu key hash
    cpukey_hash = hashlib.sha1(kv.cpu_key).digest()

    # generate the hv hash
    hv_hash = calculate_hv_hash(salt)

    # initialize flags to default values
    hv_keys_status_flags = HV_KEYS_STATUS_FLAGS
    bldr_flags = BLDR_FLAGS
    ctype = CTYPE_SEQ_ALLOW_KV2

    # handle flag conditions
    if crl:
        hv_keys_status_flags |= HV_KEYS_STATUS_FLAGS_CRL
    if kv.fcrt:
        hv_keys_status_flags |= HV_KEYS_STATUS_FLAGS_FCRT
    if kv.kv_type_one:
        bldr_flags &= BLDR_FLAGS_KV1
        ctype = CTYPE_SEQ_ALLOW_KV1

    # store flags
    struct.pack_into('>H', blob, 0x2E, bldr_flags)
    struct.pack_into('>L', blob, 0x38, hv_keys_status_flags)
    struct.pack_into('>L', blob, 0x3C, ctype)

    # store hashes
    struct.pack_into('>20s', blob, 0x50, ecchash)
    struct.pack_into('>20s', blob, 0x64, cpukey_hash)
    struct.pack_into('>6s ', blob, 0xFA, hv_hash)

    # convert blob to a string
    return str(blob)
