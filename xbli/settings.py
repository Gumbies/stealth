from xbli.utility.settings import FileProxy


class GenericConfig(object):
    MONGODB_SETTINGS = {
        'DB': 'xblse',
        'HOST': 'mongodb://xblse:xblse@ds027829.mongolab.com:27829/xblse'
    }
    SECRET_KEY = 'thisissecretormaybenothatmuch'
    SECURITY_PASSWORD_HASH = 'sha256_crypt'
    SECURITY_PASSWORD_SALT = 'supersecretsalt'
    SECURITY_CONFIRMABLE = True
    SECURITY_CHANGEABLE = True
    SECURITY_TRACKABLE = True
    SECURITY_REGISTERABLE = True


class ProductionConfig(GenericConfig):
    DEBUG = False
    FANSTATIC_OPTIONS = {
        'bottom': True,
        'minified': True
    }


@FileProxy.json('~/environment.json')
class DotcloudConfig(ProductionConfig):
    __metaclass__ = FileProxy

    MONGODB_SETTINGS = FileProxy(lambda cls, env: dict(host=env['DOTCLOUD_DATA_MONGODB_URL'] + '/admin', db='xbli'))

    LOG_FILE = '/home/dotcloud/current/app.log'


class DevelopmentConfig(GenericConfig):
    DEBUG = True
    FANSTATIC_OPTIONS = {
        'bottom': True,
    }
