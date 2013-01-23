
import webob

from swift.common.middleware import acl as swift_acl
from swift.common import utils as swift_utils
from keystoneclient.client import HTTPClient
class InvalidRoleName(Exception):
    pass

class SwiftAuth(object):
    """Swift middleware to Keystone authorization system.

    In Swift's proxy-server.conf add this middleware to your pipeline::

        [pipeline:main]
        pipeline = catch_errors cache authtoken swiftauth proxy-server

    Make sure you have the authtoken middleware before the swiftauth
    middleware.  authtoken will take care of validating the user and
    swiftauth will authorize access.  If support is required for
    unvalidated users (as with anonymous access) or for
    tempurl/formpost middleware, authtoken will need to be configured with
    delay_auth_decision set to 1.  See the documentation for more
    detail on how to configure the authtoken middleware.

    Set account auto creation to true::

        [app:proxy-server]
        account_autocreate = true

    And add a swift authorization filter section, such as::

        [filter:swiftauth]
        paste.filter_factory = swift.middleware.swiftauth:filter_factory
        operator_roles = admin, swiftoperator

    This maps tenants to account in Swift.

    The user whose able to give ACL / create Containers permissions
    will be the one that are inside the operator_roles
    setting which by default includes the admin and the swiftoperator
    roles.

    The option is_admin if set to true will allow the
    username that has the same name as the account name to be the owner.

    Example: If we have the account called savi with a user
    mfaraji that user will be admin on that account and can give ACL
    to all other users for savi.

    If you need to have a different reseller_prefix to be able to
    mix different auth servers you can configure the option
    reseller_prefix in your swiftauth entry like this :

        reseller_prefix = NEWAUTH_

    Make sure you have a underscore at the end of your new
    reseller_prefix option.

    :param app: The next WSGI app in the pipeline
    :param conf: The dict of configuration values
    """
    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        self.logger = swift_utils.get_logger(conf, log_route='swiftauth')
        self.reseller_prefix = conf.get('reseller_prefix', 'AUTH_').strip()
        self.operator_roles = conf.get('operator_roles',
                                       'admin, swiftoperator')
        self.reseller_admin_role = conf.get('reseller_admin_role',
                                            'ResellerAdmin')
        config_is_admin = conf.get('is_admin', "false").lower()
        self.is_admin = config_is_admin in swift_utils.TRUE_VALUES
        cfg_synchosts = conf.get('allowed_sync_hosts', '127.0.0.1')
        self.allowed_sync_hosts = [h.strip() for h in cfg_synchosts.split(',')
                                   if h.strip()]
        config_overrides = conf.get('allow_overrides', 't').lower()
        self.allow_overrides = config_overrides in swift_utils.TRUE_VALUES
        memcache_servers = conf.get('memcache_servers')
        if memcache_servers:
            try:
                import memcache
                import iso8601
                self.logger.info('Using memcache for caching token')
                self._cache = memcache.Client(memcache_servers.split(','))
                self._iso8601 = iso8601
            except ImportError as e:
                self.logger.warn('disabled caching due to missing libraries %s', e)
        self.auth_host = self._conf_get('auth_host')
        self.auth_port = int(self._conf_get('auth_port'))
        self.auth_protocol = self._conf_get('auth_protocol')
        self.auth_uri = self._conf_get('auth_uri')
        if self.auth_uri is None:
            self.auth_uri = '%s://%s:%s' % (self.auth_protocol,
                                            self.auth_host,
                                            self.auth_port)

        # SSL
        self.cert_file = self._conf_get('certfile')
        self.key_file = self._conf_get('keyfile')
        
        # Credentials used to verify this component with the Auth service since
        # validating tokens is a privileged call
        self.admin_token = self._conf_get('admin_token')
        self.admin_user = self._conf_get('admin_user')
        self.admin_password = self._conf_get('admin_password')
        self.admin_tenant_name = self._conf_get('admin_tenant_name')
        self.httpclient = HTTPClient(username)
        
    def __call__(self, environ, start_response):
        identity = self._keystone_identity(environ)

        # Check if one of the middleware like tempurl or formpost have
        # set the swift.authorize_override environ and want to control the
        # authentication
        if (self.allow_overrides and
                environ.get('swift.authorize_override', False)):
            msg = 'Authorizing from an overriding middleware (i.e: tempurl)'
            self.logger.debug(msg)
            return self.app(environ, start_response)

        if identity:
            self.logger.debug('Using identity: %r' % (identity))
            environ['keystone.identity'] = identity
            environ['REMOTE_USER'] = identity.get('tenant')
            environ['swift.authorize'] = self.authorize
        else:
            self.logger.debug('Authorizing as anonymous')
            environ['swift.authorize'] = self.authorize_anonymous
            
        environ['swift.clean_acl'] = swift_acl.clean_acl

        return self.app(environ, start_response)

    def _keystone_identity(self, environ):
        """Extract the identity from the Keystone auth component."""
        if environ.get('HTTP_X_IDENTITY_STATUS') != 'Confirmed':
            return
#        roles = []
#        if 'HTTP_X_ROLES' in environ:
#            roles = environ['HTTP_X_ROLES'].split(',')
        identity = {'user': environ.get('HTTP_X_USER_NAME'),
                    'tenant': (environ.get('HTTP_X_TENANT_ID'),
                               environ.get('HTTP_X_TENANT_NAME')),
                    #'roles': roles,
                    'roles_policy': environ['HTTP_X_POLICY']}
        return identity

    def _get_account_for_tenant(self, tenant_id):
        return '%s%s' % (self.reseller_prefix, tenant_id)

    def _reseller_check(self, account, tenant_id):
        """Check reseller prefix."""
        return account == self._get_account_for_tenant(tenant_id)

    def authorize(self, req):
        env = req.environ
        env_identity = env.get('keystone.identity', {})
        if not 'roles_policy' in env_identity or not env_identity['roles_policy']:
            return self.denied_response(req)
        tenant_id, tenant_name = env_identity.get('tenant')
        user_roles = env_identity.get('roles_policy', []).keys()

        
        # Getting the policies
        
        
        
        # Check whether user is admin or not
        if self.reseller_admin_role in user_roles:
            msg = 'User %s has reseller admin authorizing'
            self.logger.debug(msg % tenant_id)
            req.environ['swift_owner'] = True
            return
        

        try:
            part = swift_utils.split_path(req.path, 1, 4, True)
            version, account, container, obj = part
        except ValueError:
            return webob.exc.HTTPNotFound(request=req)

        

        

        # Check if a user tries to access an account that does not match their
        # token
        if not self._reseller_check(account, tenant_id):
            log_msg = 'tenant mismatch: %s != %s' % (account, tenant_id)
            self.logger.debug(log_msg)
            return self.denied_response(req)

        # Check the roles the user is belonging to. If the user is
        # part of the role defined in the config variable
        # operator_roles (like admin) then it will be
        # promoted as an admin of the account/tenant.
        for role in self.operator_roles.split(','):
            role = role.strip()
            if role in user_roles:
                log_msg = 'allow user with role %s as account admin' % (role)
                self.logger.debug(log_msg)
                req.environ['swift_owner'] = True
                return

        # If user is of the same name of the tenant then make owner of it.
        user = env_identity.get('user', '')
        if self.is_admin and user == tenant_name:
            req.environ['swift_owner'] = True
            return

        referrers, roles = swift_acl.parse_acl(getattr(req, 'acl', None))

        authorized = self._authorize_unconfirmed_identity(req, obj, referrers,
                                                          roles)
        if authorized:
            return
        elif authorized is not None:
            return self.denied_response(req)

        # Allow ACL at individual user level (tenant:user format)
        # For backward compatibility, check for ACL in tenant_id:user format
        if ('%s:%s' % (tenant_name, user) in roles
                or '%s:%s' % (tenant_id, user) in roles):
            log_msg = 'user %s:%s or %s:%s allowed in ACL authorizing'
            self.logger.debug(log_msg % (tenant_name, user, tenant_id, user))
            return

        # Check if we have the role in the userroles and allow it
        for user_role in user_roles:
            if user_role in roles:
                log_msg = 'user %s:%s allowed in ACL: %s authorizing'
                self.logger.debug(log_msg % (tenant_name, user, user_role))
                return

        return self.denied_response(req)

    def authorize_anonymous(self, req):
        """
        Authorize an anonymous request.

        :returns: None if authorization is granted, an error page otherwise.
        """
        try:
            part = swift_utils.split_path(req.path, 1, 4, True)
            version, account, container, obj = part
        except ValueError:
            return webob.exc.HTTPNotFound(request=req)

        is_authoritative_authz = (account and
                                  account.startswith(self.reseller_prefix))
        if not is_authoritative_authz:
            return self.denied_response(req)

        referrers, roles = swift_acl.parse_acl(getattr(req, 'acl', None))
        authorized = self._authorize_unconfirmed_identity(req, obj, referrers,
                                                          roles)
        if not authorized:
            return self.denied_response(req)

    def _authorize_unconfirmed_identity(self, req, obj, referrers, roles):
        """"
        Perform authorization for access that does not require a
        confirmed identity.

        :returns: A boolean if authorization is granted or denied.  None if
                  a determination could not be made.
        """
        # Allow container sync.
        if (req.environ.get('swift_sync_key')
            and req.environ['swift_sync_key'] ==
                req.headers.get('x-container-sync-key', None)
            and 'x-timestamp' in req.headers
            and (req.remote_addr in self.allowed_sync_hosts
                 or swift_utils.get_remote_client(req)
                 in self.allowed_sync_hosts)):
            log_msg = 'allowing proxy %s for container-sync' % req.remote_addr
            self.logger.debug(log_msg)
            return True

        # Check if referrer is allowed.
        if swift_acl.referrer_allowed(req.referer, referrers):
            if obj or '.rlistings' in roles:
                log_msg = 'authorizing %s via referer ACL' % req.referrer
                self.logger.debug(log_msg)
                return True
            return False

    def denied_response(self, req):
        """Deny WSGI Response.

        Returns a standard WSGI response callable with the status of 403 or 401
        depending on whether the REMOTE_USER is set or not.
        """
        if req.remote_user:
            return webob.exc.HTTPForbidden(request=req)
        else:
            return webob.exc.HTTPUnauthorized(request=req)
    def get_policy(self, roles_policy):
        for (role,policy) in roles_policy:
            self._cache_get(role,policy)
    
    def _cache_get(self, role,policy):
        """Return policy information from cache.
        """
        
        if self._cache and role:
            key = 'roles/%s' % role
            cached = self._cache.get(key)
            if not cached:
                self._cache_put(role)
                cached = self._cache.get(key)
            policy, expires = cached
            if expires != self._iso8601.parse_date(policy[1]).strftime('%s'):
                self._cache_put(role)
        return policy
        
    def _cache_put(self, role_name):
        # Retrieve the information
        data = {}
        if self._cache and data:
            key = 'roles/%s' % role_name
            timestamp = data['expires']
            expires = self._iso8601.parse_date(timestamp).strftime('%s')
            self.logger.debug('Storing %s Policy in memcache', role_name)
            self._cache.set(key,
                            (data, expires))
        else:
            raise InvalidRoleName('Role of the user is not valid')
            
def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return SwiftAuth(app, conf)
    return auth_filter
