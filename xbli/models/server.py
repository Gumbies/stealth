"""
Models which are related to the infernus server
"""

from datetime import datetime

from flask import request
import mongoengine as db
from Crypto.PublicKey import RSA


class Token(db.Document):
    """
    A Token is redeemable for a specific amount of time of access on the server
    """

    code = db.StringField(required=True, min_length=12, max_length=12)
    hours = db.IntField(required=True, min_value=1)
    creator = db.ReferenceField('User', required=True)

    redeemed = db.BooleanField(required=True, default=False)
    redeemed_by = db.ReferenceField('User')
    redeemed_at = db.DateTimeField()
    redeemed_ip = db.StringField()

    def __unicode__(self):
        return self.code

    @property
    def generation_time(self):
        return self.id.generation_time

    def redeem(self, user, ip):
        """
        Attempts to redeem a token, returning True if successful
        """

        # cannot redeem twice
        if self.redeemed:
            return False

        # store redeeming information
        self.redeemed_by = user
        self.redeemed_at = datetime.now()
        self.redeemed_ip = ip

        # update the token
        self.save()

        return True


class ConsoleKeyVaultHistory(db.Document):
    """
    Maps a console to a key vault, recording the times used
    """

    key_vault = db.ReferenceField('KeyVault', required=True)
    console = db.ReferenceField('Console', required=True, unique_with='key_vault')
    history = db.ListField(db.EmbeddedDocumentField('ConsoleLoginRecord'))

    def __unicode__(self):
        return u'console {0.console.cpu_key} using kv {0.key_vault.hash}'.format(self)

    def use_from_request(self):
        self.update(add_to_set__history=ConsoleLoginRecord.from_request())

    @classmethod
    def from_request(cls, console, key_vault):
        record, created = cls.objects.get_or_create(console=console, key_vault=key_vault)
        return record


class ConsoleLoginRecord(db.EmbeddedDocument):
    """
    Records a single login of a console
    """

    at = db.DateTimeField(required=True, default=datetime.now)
    ip = db.StringField(required=True)

    def __unicode__(self):
        return u'{0} from {1}'.format(self.at, self.ip)

    @classmethod
    def from_request(cls):
        return cls(ip=request.remote_addr)


class ConsolePublicKey(db.Document):
    """
    Storage of public keys by console
    """

    cpu_key = db.StringField(required=True, unique=True, min_length=32, max_length=32)
    public_key = db.BinaryField(required=True, max_bytes=1024)
    updated_at = db.DateTimeField(required=True, default=datetime.now)

    def __unicode__(self):
        return self.cpu_key

    @classmethod
    def pre_save(cls, sender, document, **kwargs):
        document.updated_at = datetime.now()

    @classmethod
    def set(cls, cpu_key, public_key):
        cpk, created = cls.objects.get_or_create(cpu_key=str(cpu_key), defaults={'public_key': public_key})
        if not created:
            cpk.public_key = public_key
            cpk.save()

    @classmethod
    def get(cls, cpu_key):
        from xbli.api.utility.rsa import RSAKey

        # find the public key
        try:
            cpk = cls.objects.get(cpu_key=str(cpu_key))
        except db.DoesNotExist:
            return False

        # load the public key
        try:
            return RSAKey(public_key=RSA.importKey(cpk.public_key))
        except ValueError:
            # public key is not valid, just delete this record
            cpk.delete()
            return False

db.signals.pre_save.connect(ConsolePublicKey.pre_save, sender=ConsolePublicKey)


class ApiLog(db.Document):
    """
    Logs all api action details
    """

    action = db.StringField(
        choices=(
            ('auth', 'Auth'),
            ('invalid_command', 'Invalid Command'),
            ('bad_request', 'Bad Request'),
            ('malicious_request', 'Malicious Request'),
            ('needs_authentication', 'Needs Authentication'),
            ('not_authorized', 'Not Authorized'),
            ('announce_command', 'Announce Command'),
            ('sendkv_command', 'Send KV Command'),
            ('xekeysexecute_command', 'XeKeysExecute Command'),
            ('xosc_command', 'XOSC Command')
        )
    )
    details = db.StringField()
    cpu_key = db.StringField(max_length=32)
    ip = db.StringField(required=True)
    at = db.DateTimeField(required=True, default=datetime.now)

    def __unicode__(self):
        return u'[{0.action}] {0.ip} @ {0.at} {0.cpu_key} - {0.details}'.format(self)

    @classmethod
    def log(cls, action, details=None):
        """
        Log an action on the API
        """

        from xbli.api.utility import local

        entry = cls()
        entry.action = action
        entry.details = details
        entry.cpu_key = str(local.cpu_key)
        entry.ip = request.remote_addr
        entry.save()

        # if app.debug:
        print u'{0}'.format(entry)
