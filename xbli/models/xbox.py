"""
Models which relate to the xbox
"""

import mongoengine as db
import struct
from datetime import datetime
from Crypto.Hash import HMAC, SHA
from flask import request
from xbli.models.utility import CompressedBinaryField
from xbli.models.server import ConsoleLoginRecord, ConsoleKeyVaultHistory
from xbli.utility import read_count
from xbli.utility.cpukey import is_valid_for_kv


class KeyVault(db.Document):
    """
    An Xbox 360 key vault, which allows access to xbox live
    """

    hash = db.StringField(required=True, unique=True)
    cpu_key = db.StringField(required=True, default='', min_length=32, max_length=32)
    cpu_key_verified = db.BooleanField(required=True, default=False)
    kv_type_one = db.BooleanField(required=True, default=False)
    fcrt = db.BooleanField(required=True, default=False)
    blob = CompressedBinaryField(required=True)

    def __unicode__(self):
        return self.hash

    @property
    def digest(self):
        h = HMAC.new(self.cpu_key.decode('hex'), digestmod=SHA)
        h.update(read_count(self.blob, 0x1C, 0xD4))
        h.update(read_count(self.blob, 0x100, 0x1CF8))
        h.update(read_count(self.blob, 0x1EF8, 0x2108))
        return h.digest()

    @classmethod
    def create(cls, blob, cpu_key):
        hmac = read_count(blob, 0, 16).encode('hex')
        kv = cls(hash=hmac, blob=blob, cpu_key=cpu_key.encode('hex'))
        kv.cpu_key_verified, kv.kv_type_one = is_valid_for_kv(kv)
        (odd_features, ) = struct.unpack_from('>H', blob, 0x1C)
        kv.fcrt = (odd_features & 0x120) != 0
        kv.save(force_insert=True)
        return kv

    @classmethod
    def get(cls, kv_hash):
        try:
            return cls.objects.get(hash=kv_hash)
        except db.DoesNotExist:
            return False


class Console(db.Document):
    """
    A Console is a physical Xbox 360 console which has connected to our service
    """

    user = db.ReferenceField('User')
    cpu_key = db.StringField(required=True, unique=True, min_length=32, max_length=32)
    current_key_vault = db.ReferenceField(KeyVault)

    last_login_at = db.DateTimeField(required=True, default=datetime.now)
    last_login_ip = db.StringField(required=True, default='')

    expires = db.DateTimeField(required=True, default=datetime.now)

    # records the dates and ip's from which a console authenticates
    login_history = db.ListField(db.EmbeddedDocumentField('ConsoleLoginRecord'))

    def __unicode__(self):
        return self.cpu_key

    def login_from_request(self):
        self.update(set__last_login_at=datetime.now(), set__last_login_ip=request.remote_addr,
                    add_to_set__login_history=ConsoleLoginRecord.from_request())

    def use_kv_from_request(self, key_vault):
        self.update(set__current_key_vault=key_vault)
        ConsoleKeyVaultHistory.from_request(self, key_vault).use_from_request()

    @classmethod
    def get(cls, cpu_key):
        try:
            return cls.objects.get(cpu_key=str(cpu_key))
        except db.DoesNotExist:
            return False
