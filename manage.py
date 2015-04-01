#!/usr/bin/env python

from datetime import datetime
from flask.ext.script import Manager, Server
from flask_security.utils import encrypt_password
from werkzeug.wsgi import DispatcherMiddleware
from werkzeug.serving import run_simple
from xbli.site.application import app
from xbli.api.application import app as api


class WsgiServer(Server):
    application = DispatcherMiddleware(app, {
        '/api': api
    })

    def handle(self, app, host, port, use_debugger, use_reloader, threaded, processes, passthrough_errors):
            api.debug = use_debugger
            app.debug = use_debugger
            run_simple(host, port, self.application,
                       use_debugger=use_debugger,
                       use_reloader=use_reloader,
                       threaded=threaded,
                       processes=processes,
                       passthrough_errors=passthrough_errors,
                       **self.server_options)

manager = Manager(app)

server = WsgiServer(
    use_debugger=True,
    use_reloader=True,
    host='0.0.0.0',
    port='8000'
)

manager.add_command('runserver', server)


@manager.command
def createsuperuser():
    """
    Creates a superuser
    """
    user_info = dict(
        email='admin@admin.com',
        password=encrypt_password('password'),
        confirmed_at=datetime.now()
    )
    user = app.userstore.get_user(user_info['email'])
    if user is not None:
        if user.password != user_info['password']:
            user.password = user_info['password']
            user.confirmed_at = datetime.now()
            user.save()
            print 'Admin password updated'
            return
        print 'Admin user already exists'
        return

    user = app.userstore.create_user(**user_info)
    admin_role = app.userstore.find_or_create_role('admin', description='Administrators have full control')
    app.userstore.add_role_to_user(user, admin_role)
    print 'Admin user created'


if __name__ == '__main__':
    manager.run()
