from flask import url_for, flash, redirect, current_app

from flask.ext import wtf
from flask.ext.wtf.file import FileField
from flask.ext.superadmin import Admin, AdminIndexView, BaseView, form
from flask.ext.superadmin.base import expose
from flask.ext.superadmin.model.backends.mongoengine import ModelAdmin
from flask_security.core import current_user
from xbli.models import User, Role, Token, KeyVault, Console, ApiLog, ConsoleKeyVaultHistory


class AuthMixin(object):
    def is_accessible(self):
        # only allow authenticated users
        if not current_user.is_active():
            return False

        # check for required roles
        roles = getattr(self, 'required_roles', None)
        if roles is not None:
            for role in roles:
                if not current_user.has_role(role):
                    return False
            else:
                return True

        # check for allowed roles
        roles = getattr(self, 'allowed_roles', None)
        if roles is not None:
            for role in roles:
                if current_user.has_role(role):
                    return True
            else:
                return False

        # default case of allowed
        return True

    def _handle_view(self, name, *args, **kwargs):
        if not self.is_accessible():
            return current_app.login_manager.unauthorized()


class AdminIndex(AuthMixin, AdminIndexView):
    pass


class BaseModelAdmin(AuthMixin, ModelAdmin):
    pass


class UploadForm(form.BaseForm):
    upload = FileField()

    def __init__(self, file_name):
        self.upload.args = ('Select {0}'.format(file_name), )
        super(UploadForm, self).__init__()

    def validate_upload(self, field):
        if not self.upload.has_file():
            raise wtf.ValidationError('File required.')


class GridFileAdmin(AuthMixin, BaseView):
    required_roles = ['admin']

    default_items = (
        'HV.bin',
    )

    list_template = 'admin/gridfs/list.html'
    upload_template = 'admin/gridfs/upload.html'

    def field_name(self, text):
        return text.capitalize()

    def get_readonly_fields(self, instance):
        return {}

    def sizeof_fmt(self, num):
        for x in ['bytes', 'KB', 'MB', 'GB']:
            if num < 1024.0:
                return "%3.1f%s" % (num, x)
            num /= 1024.0
        return "%3.1f%s" % (num, 'TB')

    @expose('/')
    def index(self):

        # load default empty items
        items = dict([(i, [i, 'Not Found', '-']) for i in self.default_items])

        # fill in entries from gridfs
        for file_name in current_app.fs.list():
            doc = current_app.fs.get_last_version(file_name)
            if doc.filename in items:
                items[doc.filename][1] = self.sizeof_fmt(doc.length)
                items[doc.filename][2] = doc.upload_date

        return self.render(self.list_template, items=items.values())

    @expose('/upload/<file_name>', methods=('GET', 'POST'))
    def upload(self, file_name=None):
        upload_form = UploadForm(file_name)

        if upload_form.validate_on_submit():
            try:
                current_app.fs.put(upload_form.upload.data, filename=file_name)
                return redirect(url_for('.index'))
            except Exception as ex:
                flash("Failed to save file: {0}".format(ex))

        return self.render(self.upload_template, form=upload_form, file_name=file_name)


class UserAdmin(BaseModelAdmin):
    list_display = ('email', 'active', 'roles')


class ApiLogAdmin(BaseModelAdmin):
    list_display = ('action', 'ip', 'at', 'cpu_key', 'details')


class ConsoleKeyVaultHistoryAdmin(BaseModelAdmin):
    list_display = ('console', 'key_vault')


class InfernusAdmin(Admin):
    """
    Super admin customized for infernus
    """

    def __init__(self, *args, **kwargs):
        kwargs['name'] = 'Infernus Control Panel'
        kwargs['index_view'] = AdminIndex()
        super(InfernusAdmin, self).__init__(*args, **kwargs)

        self.register(User, UserAdmin)
        self.register(Role, BaseModelAdmin)
        self.register(Token, BaseModelAdmin)
        self.register(KeyVault, BaseModelAdmin)
        self.register(Console, BaseModelAdmin)
        self.register(ApiLog, ApiLogAdmin)
        self.register(ConsoleKeyVaultHistory, ConsoleKeyVaultHistoryAdmin)

        self.add_view(GridFileAdmin())
