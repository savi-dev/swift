from swift.common.middleware.acl import \
    clean_acl, parse_acl, referrer_allowed
from webob.exc import HTTPForbidden, HTTPUnauthorized
from swift.common.utils import cache_from_env, get_logger, get_remote_client, \
    split_path, TRUE_VALUES


class Authorization(object):
    """Test authentication and authorization system.

    Add to your pipeline in proxy-server.conf, such as::

        [pipeline:main]
        pipeline = catch_errors cache tempauth proxy-server

    Set account auto creation to true in proxy-server.conf::

        [app:proxy-server]
        account_autocreate = true

    And add a tempauth filter section, such as::

        [filter:tempauth]
        use = egg:swift#tempauth
        user_admin_admin = admin .admin .reseller_admin
        user_test_tester = testing .admin
        user_test2_tester2 = testing2 .admin
        user_test_tester3 = testing3

    See the proxy-server.conf-sample for more information.

    :param app: The next WSGI app in the pipeline
    :param conf: The dict of configuration values
    """
    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        self.logger = get_logger(conf, log_route='saviauth')
        self.log_headers = conf.get('log_headers') == 'True'
        self.reseller_prefix = conf.get('idp_prefix', 'AUTH').strip()
        if self.reseller_prefix and self.reseller_prefix[-1] !='_':
            self.reseller_prefix +='_'
        self.logger.set_statsd_prefix('saviauth.%s' % (
                self.reseller_prefix if self.reseller_prefix else None))
        self.auth_prefix = conf.get('auth_prefix', '/auth/')
        if not self.auth_prefix:
            self.auth_prefix = '/auth/'
        if self.auth_prefix[0] !='/':
            self.auth_prefix = '/' + self.auth_prefix
        if self.auth_prefix[-1] !='/':
            self.auth_prefix +='/'
        self.token_life = int(conf.get('token_life', 86400))
        self.allowed_sync_hosts = [h.strip()
            for h in conf.get('allowed_sync_hosts', '127.0.0.1').split(',')
            if h.strip()]
        self.allow_overrides = \
            conf.get('allow_overrides', 't').lower() in TRUE_VALUES
        self.users = {}

    def __call__(self, environ, start_response):
        """
        Accepts a standard WSGI application call, installing callback hooks for
        authorization and ACL header validation. For an authenticated request,
        REMOTE_USER will be set to a comma separated list of the user's groups.

        With a non-empty reseller prefix, acts as the definitive auth service
        for just tokens and accounts that begin with that prefix, but will deny
        requests outside this prefix if no other auth middleware overrides it.

        With an empty reseller prefix, acts as the definitive auth service only
        for tokens that validate to a non-empty set of groups. For all other
        requests, acts as the fallback auth service when no other auth
        middleware overrides it.

        Alternatively, if the request matches the self.auth_prefix, the request
        will be routed through the internal auth request handler (self.handle).
        This is to handle granting tokens, etc.
        """
        environ['swift.authorize'] = self.authorize
        environ['swift.clean_acl'] = clean_acl
        return self.app(environ, start_response)

    def authorize(self, req):
        if hasattr(req, 'acl'):
            referrers, groups = parse_acl(req.acl)
            if req.method == 'GET' and referrer_allowed(req, referrers):
                return None
            if req.remote_user and groups and req.remote_user in groups:
                return None
        if req.remote_user:
            return HTTPForbidden(request=req)
        else:
            return HTTPUnauthorized(request=req)

def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    def auth_filter(app):
        return Authorization(app, conf)
    return auth_filter