from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes
from xbli.utility import read_count


n = int('AEB8FC77CBFBAB8AF953478F74A38E7B2797558207F2F3AAEA1D478CE1F390138A357BAB354EBB87B4647986EAECB6DED312CF838D8156'
        '000C24513D39364A3F6C80B51B7A0C02CE7C60D744E5CD8BEAB0C13C250DAED1826574206FF25C52E4A05AA30F9FADFE129E2FCD8D4EF5'
        'CEC26E4D7887D42A7F6BD0C19A12CC3A17BF59D71B99DAC4DF7BE5028F3CA19AEB93F65E2A56BAD0A82438E1D38B1F96BD84E41FFD96D9'
        '3A782590EDDE4EEC86103F02E40D1AC1369FBBD8288CFF03DCC4351EE55B8FBF358E63A02A4233853453830E5F5A5B084BADE238CDA0E5'
        '857201F9E6923A79DB3B63AFBED310FD3CA4D4ACE45B98F25DA6B843DD5F496F994D37BB', 16)
e = 0x3L
master_key = RSA.construct((n, e))


def is_valid(cpu_key):
    """
    Checks if an xbox 360 cpu key is valid based on its internal ecc data and cryptographic security
    """

    # check key length
    if len(cpu_key) != 16:
        return False

    # convert the key to an integer, removing the ecc
    cpu_key_int = int(cpu_key.encode('hex'), 16) & (~0xFCFFFF)

    # count set bits
    set_bit_count = len(bin(cpu_key_int)[2:].replace('0', ''))

    # valid keys have 53 bits set
    if set_bit_count != 53:
        return False

    # calculate ecc from the original cpukey
    cpu_key_bytes = [ord(c) for c in cpu_key]

    acc1 = acc2 = 0
    for cnt in range(0, 0x80):
        b = cpu_key_bytes[cnt >> 3]
        d = (b >> (cnt & 7)) & 1

        if cnt < 0x6A:
            acc1 = d ^ acc1
            if acc1 & 1:
                acc1 ^= 0x360325
            acc2 = d ^ acc2
        elif cnt < 0x7F:
            if d != (acc1 & 1):
                cpu_key_bytes[cnt >> 3] = (1 << (cnt & 7)) ^ b
            acc2 = (acc1 & 1) ^ acc2
        elif d != acc2:
            cpu_key_bytes[0xF] = (0x80 ^ b) & 0xFF
        acc1 >>= 1
    cpu_key_ecc = ''.join([chr(c) for c in cpu_key_bytes])

    return cpu_key == cpu_key_ecc


def is_valid_for_kv(kv):
    """
    Checks if the cpu key is valid for the given keyvault

    Returns (valid, type_one)
    """

    sig = read_count(kv.blob, 0x1DF8, 0x100)[::-1]
    sig = bytes_to_long(sig)
    type_one = sig == 0
    sig = long_to_bytes(master_key.encrypt(sig, 0)[0])
    valid = sig.endswith(kv.digest)

    return valid, type_one
