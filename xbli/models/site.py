"""
Models relating to the infernus site
"""

import mongoengine as db
from flask.ext.security import UserMixin, RoleMixin


class Role(db.Document, RoleMixin):
    name = db.StringField(max_length=80, unique=True)
    description = db.StringField(max_length=255)

    def __unicode__(self):
        return self.name


class User(db.Document, UserMixin):
    email = db.StringField(max_length=255)
    password = db.StringField(max_length=255)
    active = db.BooleanField(default=True)
    confirmed_at = db.DateTimeField()
    last_login_at = db.DateTimeField()
    current_login_at = db.DateTimeField()
    last_login_ip = db.StringField()
    current_login_ip = db.StringField()
    login_count = db.IntField()
    roles = db.ListField(db.ReferenceField(Role), default=[])

    # the hours of credit the user has remaining
    hours = db.IntField(required=True, min_value=0, default=0)

    def __unicode__(self):
        return self.email
