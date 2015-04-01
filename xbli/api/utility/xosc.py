import hashlib
import struct

from xbli.utility import read_count


# variables
HV_KEYS_STATUS_FLAGS = 0x023289D3
HV_KEYS_STATUS_FLAGS_CRL = 0x10000
HV_KEYS_STATUS_FLAGS_FCRT = 0x1000000
BLDR_FLAGS = 0xD83E
BLDR_FLAGS_KV1 = (~0x20)

SEC_FUSES_KEY = '\x52\x7A\x5A\x4B\xD8\xF5\x05\xBB\x94\x30\x5A\x17\x79\x72\x9F\x3B'
HARDWARE_INFO_FLAGS = 0x40000207
CRL_VERSION = 0x00000006
HV_PROTECTED_FLAGS_NONE = 0
HV_PROTECTED_FLAGS_NO_EJECT_REBOOT = 1
HV_PROTECTED_FLAGS_DISC_AUTH = 2
HV_PROTECTED_FLAGS_AUTH_EX_CAP = 4
XOSC_VER_MAJOR = 0x0009
XOSC_VER_MINOR = 0x0002
XOSC_DAE_VALUE = 0x000D000800000008
XOSC_FLAG_BASE = 0x00000000000002BB
XOSC_FLAG_EXE = 0x4
XOSC_FLAG_SHOULD_EXIT = 0x2000000000000000
XOSC_FLAG_TERM_PENDING = 0x4000000000000000
XOSC_REGION_POL = 0x70000
XOSC_FOOTER = 0x5F534750


def calculate_from_keyvault(kv, hv_protected_flags, crl, term_pending, should_exit, exe_id_res, exe_id, mu_part_sizes):
    """
    calculate the xosc response from the given kv and parameters
    """

    # create an empty blob of 0x400 bytes
    blob = bytearray(0x400)

    # fill with 0xAA in the response portion
    blob[:0x2E0] = '\xAA' * 0x2E0

    # initialize variables to default values
    dvd_ioctl_result = 0
    xekeysgetkey_result = 0
    console_id_result = 0
    unk_hash_result = 0xC8003003
    dae_result = 0
    media_type = 0
    title_id = 0
    serial_byte = 0
    beta_bldr = 0
    kv_restricted_privs = 0

    # initialize flags to default values
    hv_keys_status_flags = HV_KEYS_STATUS_FLAGS
    hv_protected_flags = HV_PROTECTED_FLAGS_AUTH_EX_CAP | (hv_protected_flags & HV_PROTECTED_FLAGS_NO_EJECT_REBOOT)
    bldr_flags = BLDR_FLAGS
    operation_flags = XOSC_FLAG_BASE

    # read data from key vault
    drive_phase_level = ord(read_count(kv.blob, 0xC89, 0x1))
    drive_data = read_count(kv.blob, 0xC8A, 0x24)
    console_id = read_count(kv.blob, 0x9CA, 0x5)
    console_serial = read_count(kv.blob, 0xB0, 0xC)
    xam_region = struct.unpack_from('>H', kv.blob, 0xC8)[0]
    xam_odd = struct.unpack_from('>H', kv.blob, 0x1C)[0]
    policy_flash_size = struct.unpack_from('>L', kv.blob, 0x24)[0]

    # generate cpu key hash
    cpukey_hash = hashlib.sha1(kv.cpu_key).digest()

    # handle flag conditions
    if crl:
        hv_keys_status_flags |= HV_KEYS_STATUS_FLAGS_CRL
    if kv.fcrt:
        hv_keys_status_flags |= HV_KEYS_STATUS_FLAGS_FCRT
    if kv.kv_type_one:
        bldr_flags &= BLDR_FLAGS_KV1
        policy_flash_size = 0
    if exe_id_res >= 0:
        operation_flags |= XOSC_FLAG_EXE
    if term_pending:
        operation_flags |= XOSC_FLAG_TERM_PENDING
    if should_exit:
        operation_flags |= XOSC_FLAG_SHOULD_EXIT

    # set variables
    struct.pack_into('>LHH', blob, 0x000, 0, XOSC_VER_MAJOR, XOSC_VER_MINOR)
    struct.pack_into('>Q  ', blob, 0x008, operation_flags)
    struct.pack_into('>L  ', blob, 0x010, dvd_ioctl_result)
    struct.pack_into('>L  ', blob, 0x014, xekeysgetkey_result)
    struct.pack_into('>L  ', blob, 0x018, exe_id_res)
    struct.pack_into('>L  ', blob, 0x01C, console_id_result)
    struct.pack_into('>L  ', blob, 0x020, unk_hash_result)
    struct.pack_into('>L  ', blob, 0x034, dae_result)
    struct.pack_into('>16s', blob, 0x050, cpukey_hash)
    struct.pack_into('>16s', blob, 0x060, kv.digest)
    struct.pack_into('>16s', blob, 0x070, SEC_FUSES_KEY)
    struct.pack_into('>L  ', blob, 0x080, drive_phase_level)
    struct.pack_into('>36s', blob, 0x0F0, drive_data)
    struct.pack_into('>36s', blob, 0x114, drive_data)
    struct.pack_into('>12s', blob, 0x138, console_serial)
    struct.pack_into('>B  ', blob, 0x144, serial_byte)
    struct.pack_into('>H  ', blob, 0x146, bldr_flags)
    struct.pack_into('>H  ', blob, 0x148, xam_region)
    struct.pack_into('>H  ', blob, 0x14A, xam_odd)
    struct.pack_into('>L  ', blob, 0x14C, beta_bldr)
    struct.pack_into('>L  ', blob, 0x150, policy_flash_size)
    struct.pack_into('>L  ', blob, 0x154, XOSC_REGION_POL)
    struct.pack_into('>L  ', blob, 0x158, hv_keys_status_flags)
    struct.pack_into('>LLL', blob, 0x160, 0, 0, 0)  # padding and unknown
    struct.pack_into('>Q  ', blob, 0x170, XOSC_DAE_VALUE)
    struct.pack_into('>LL ', blob, 0x178, 0, 0)  # unknown
    struct.pack_into('>Q  ', blob, 0x180, kv_restricted_privs)
    struct.pack_into('>16x', blob, 0x188)  # zero sec data
    struct.pack_into('>Q  ', blob, 0x198, hv_protected_flags)
    struct.pack_into('>5s ', blob, 0x1A0, console_id)
    struct.pack_into('>43x', blob, 0x1A5)  # zero rest of console id
    struct.pack_into('>L  ', blob, 0x1D0, HARDWARE_INFO_FLAGS)
    struct.pack_into('>72x', blob, 0x1D4)  # zero out hdd structures
    struct.pack_into('>28s', blob, 0x2A8, mu_part_sizes)
    struct.pack_into('>L  ', blob, 0x2C4, CRL_VERSION)
    struct.pack_into('>L  ', blob, 0x2D8, XOSC_FOOTER)

    # set execution id if successful result
    if exe_id_res >= 0:
        struct.pack_into('>24s', blob, 0x38, exe_id)
        struct.pack_into('>LL ', blob, 0x84, media_type, title_id)

    # convert blob to a string
    return str(blob)
