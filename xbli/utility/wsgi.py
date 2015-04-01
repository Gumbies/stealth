from werkzeug.contrib.fixers import ProxyFix


class DotCloudProxyFix(ProxyFix):
    """
    Use the forwarded host and remote ip from dotcloud
    """

    def __call__(self, environ, start_response):
        getter = environ.get
        forwarded_for = getter('HTTP_X_FORWARDED_FOR', '').split(',')
        forwarded_host = getter('HTTP_X_FORWARDED_HOST', '')
        environ.update({
            'werkzeug.proxy_fix.orig_remote_addr': getter('REMOTE_ADDR'),
            'werkzeug.proxy_fix.orig_http_host': getter('HTTP_HOST')
        })
        if forwarded_for:
            forwarded_for = forwarded_for[0].strip()
            environ['REMOTE_ADDR'] = forwarded_for.replace('::ffff:', '')
        if forwarded_host:
            environ['HTTP_HOST'] = forwarded_host
        return self.app(environ, start_response)
