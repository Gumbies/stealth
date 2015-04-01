import struct

from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey.RSA import generate as generate_rsa

from xbli.utility import read_count

__all__ = ['RSAKey', 'RandomRSAKey']


pad = lambda s: s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)
unpad = lambda s: s[0:-ord(s[-1])]


class RSAKey(object):
    """
    A class which contains an rsa key
    """

    def __init__(self, rsa_key=None, public_key=None):
        if not rsa_key and not public_key:
            raise RuntimeError('neither private or public pairs set')

        self.rsa_key = rsa_key
        self.public_key = public_key

        if not public_key:
            self.public_key = rsa_key.publickey()

    @property
    def data(self):
        if self.rsa_key:
            return self.rsa_key.exportKey('DER')
        return None

    @property
    def public_data(self):
        if self.public_key:
            return self.public_key.exportKey('DER')
        return None

    def encrypt(self, plaintext):
        if not self.public_key:
            raise RuntimeError('this key cannot encrypt')

        cipher = PKCS1_OAEP.new(self.public_key)
        return cipher.encrypt(plaintext)

    def decrypt(self, ciphertext):
        if not self.rsa_key:
            raise RuntimeError('this key cannot encrypt')

        cipher = PKCS1_OAEP.new(self.rsa_key)
        return cipher.decrypt(ciphertext)

    def aes_encrypt(self, plaintext):
        data = pad(plaintext)
        aes_key = Random.new().read(AES.block_size)
        iv = Random.new().read(AES.block_size)

        aes = AES.new(aes_key, AES.MODE_CBC, iv)
        data = aes.encrypt(data)

        key_data = self.encrypt(aes_key + iv)
        key_len = len(key_data)

        return struct.pack('!L', key_len) + key_data + data

    def aes_decrypt(self, ciphertext):
        key_len = struct.unpack('!L', read_count(ciphertext, 0, 4))[0]

        # check the key data length
        if key_len + 4 + 16 >= len(ciphertext):
            raise ValueError('Key length is out of range: {0}'.format(key_len))

        key_data = read_count(ciphertext, 4, key_len)
        key_data = self.decrypt(key_data)
        aes_key = read_count(key_data, 0, 16)
        iv = read_count(key_data, 16, 16)

        aes = AES.new(aes_key, AES.MODE_CBC, iv)

        data = aes.decrypt(ciphertext[4 + key_len:])
        return unpad(data)


class RandomRSAKey(RSAKey):
    """
    A class which generates a random RSA key upon creation
    """

    def __init__(self, bits=2048):
        super(RandomRSAKey, self).__init__(rsa_key=generate_rsa(bits))
