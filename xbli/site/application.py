from flask_fanstatic import Fanstatic
from flask.ext.security import Security, MongoEngineUserDatastore

from xbli.application import create_common_application
from xbli.site.admin import InfernusAdmin

app = create_common_application(__name__)
app.admin = InfernusAdmin(app)

fanstatic = Fanstatic(app)
fanstatic.resource('css/app.css', name='app_css')
fanstatic.resource('js/app.js', name='app_js', bottom=True)

from xbli.utility import wtf
wtf.add_helpers(app)

# imports
from xbli import models
from xbli.site import views  # noqa

# Setup Flask-Security
app.userstore = MongoEngineUserDatastore(app.db, models.User, models.Role)
app.security = Security(app, app.userstore)
