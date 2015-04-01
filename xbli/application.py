import os
from flask import Flask
from flask.ext.mongoengine import MongoEngine
from gridfs import GridFS


def get_config():
    """
    Determine the configuration to use based on `XBLI_ENV` environment variable
    """

    env = os.environ.get('FLASK_ENV', '')
    if env == 'DOTCLOUD':
        return 'xbli.settings.DotcloudConfig'
    elif env == 'PRODUCTION':
        return 'xbli.settings.ProductionConfig'
    else:
        return 'xbli.settings.DevelopmentConfig'


def create_common_application(name):
    app = Flask(name)
    app.config.from_object(get_config())
    app.db = MongoEngine(app)
    app.fs = GridFS(app.db.connection.get_default_database())

    # configure logging
    if app.config.get('LOG_FILE', False):
        import logging
        from logging.handlers import RotatingFileHandler
        file_handler = RotatingFileHandler(app.config.get('LOG_FILE'))
        file_handler.setLevel(logging.WARNING)
        app.logger.addHandler(file_handler)

    return app
