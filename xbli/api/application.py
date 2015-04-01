from gridfs.errors import NoFile
from werkzeug.local import LocalProxy

from Crypto.PublicKey.RSA import importKey as import_rsa

from xbli.api import InfernusApi
from xbli.api.utility import malicious_request_action, local
from xbli.api.utility.rsa import RSAKey, RandomRSAKey
from xbli.application import create_common_application


app = create_common_application(__name__)
app.api = InfernusApi(app)


def get_rsa_key():
    if not local.rsa_key:
        try:
            data = app.fs.get_last_version('rsa-private-key.bin').read()
            local.set_rsa_key(RSAKey(import_rsa(data)))
        except NoFile:
            local.set_rsa_key(RandomRSAKey())
            data = local.rsa_key.data
            app.fs.put(data, filename='rsa-private-key.bin')
    return local.rsa_key


app.rsa_key = LocalProxy(get_rsa_key)


@app.route('/')
def index():
    """
    Redirect by default for the api application
    """

    return malicious_request_action()
