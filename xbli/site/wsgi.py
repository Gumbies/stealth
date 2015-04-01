import sys
sys.path.append('/home/dotcloud/code')

from xbli.site.application import app as application
from xbli.utility.wsgi import DotCloudProxyFix
from werkzeug.contrib.fixers import HeaderRewriterFix

application = DotCloudProxyFix(HeaderRewriterFix(application, remove_headers=['Date', 'Server']))
