'''
Created on Jan 15, 2013

@author: Mohammad Faraji<ms.faraji@utoronto.ca>
'''
import webob

from swift.common.middleware import acl as swift_acl
from swift.common import utils as swift_utils
from keystoneclient.client import HTTPClient


class ServiceError(Exception):
    pass

class ConfigurationError(Exception):
    pass

class AuthZ(object):
    """AuthZ middleware to Keystone authorization system.

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
        self.reseller_admin_role = conf.get('reseller_admin_role',
                                            'ResellerAdmin')
        config_is_admin = conf.get('is_admin', "false").lower()
        self.is_admin = config_is_admin in swift_utils.TRUE_VALUES
        cfg_synchosts = conf.get('allowed_sync_hosts', '127.0.0.1')
        self.allowed_sync_hosts = [h.strip() for h in cfg_synchosts.split(',')
                                   if h.strip()]
        config_overrides = conf.get('allow_overrides', 't').lower()
        self.allow_overrides = config_overrides in swift_utils.TRUE_VALUES
        self.authz_host = self.conf.get('authz_host')
        self.authz_port = self.conf.get('authz_port')
        self.authz_protocol = self.conf.get('authz_protocol')
        self.authz_uri = self.conf.get('authz_uri')
        if self.authz_uri is None:
            self.authz_uri = '%s://%s:%s' % (self.authz_protocol,
                                            self.authz_host,
                                            self.authz_port)
        # SSL
        self.cert_file = self.conf.get('certfile')
        self.key_file = self.conf.get('keyfile')
        
        # Credentials used to verify this component with the Auth service since
        # validating tokens is a privileged call
        self.admin_token = self.conf.get('admin_token')
        self.admin_user = self.conf.get('admin_user')
        self.admin_password = self.conf.get('admin_password')
        self.admin_tenant_name = self.conf.get('admin_tenant_name')
        
        # Creating Client
        if self.
        self.httpClient = HTTPClient(username=self.admin_user,
                                     password=self.admin_password)

        
        
        
        
    def __call__(self, environ, start_response):
        """Authorize incoming request.

        Authorize and send downstream on success. Reject request if
        we can't authorize.

        """
        self.logger.debug('Authorizing User Request')
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
        roles = []
        if 'HTTP_X_ROLES' in environ:
            roles = environ['HTTP_X_ROLES'].split(',')
        identity = {'user': environ.get('HTTP_X_USER_NAME'),
                    'tenant': (environ.get('HTTP_X_TENANT_ID'),
                               environ.get('HTTP_X_TENANT_NAME')),
                    'roles': roles}
        return identity

    def _get_account_for_tenant(self, tenant_id):
        return '%s%s' % (self.reseller_prefix, tenant_id)

    def _reseller_check(self, account, tenant_id):
        """Check reseller prefix."""
        return account == self._get_account_for_tenant(tenant_id)

    def authorize(self, req):
        self.logger.debug("Entering Authorization Process")
        env = req.environ
        env_identity = env.get('keystone.identity', {})
        tenant_id, tenant_name = env_identity.get('tenant')

        try:
            part = swift_utils.split_path(req.path, 1, 4, True)
            version, account, container, obj = part
        except ValueError:
            return webob.exc.HTTPNotFound(request=req)

        user_roles = env_identity.get('roles', [])

        # Give unconditional access to a user with the reseller_admin
        # role.
        if self.reseller_admin_role in user_roles:
            msg = 'User %s has reseller admin authorizing'
            self.logger.debug(msg % tenant_id)
            req.environ['swift_owner'] = True
            return

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
    
    def _get_policy(self,method.path):
        

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
        
        
        
    def _check(self, match, target_dict, cred_dict):
        match_kind, match_value = match.split(':', 1)
        try:
            f = getattr(self, '_check_%s' % match_kind)
        except AttributeError:
            if not self._check_generic(match, target_dict, cred_dict):
                return False
        else:
            if not f(match_value, target_dict, cred_dict):
                return False
        return True

    def check(self, match_list, target_dict, cred_dict):
        """Checks authorization of some rules against credentials.

        Detailed description of the check with examples in policy.enforce().

        :param match_list: nested tuples of data to match against
        :param target_dict: dict of object properties
        :param credentials_dict: dict of actor properties

        :returns: True if the check passes

        """
        if not match_list:
            return True
        for and_list in match_list:
            if isinstance(and_list, basestring):
                and_list = (and_list,)
            if all([self._check(item, target_dict, cred_dict)
                    for item in and_list]):
                return True
        return False

    def _check_rule(self, match, target_dict, cred_dict):
        """Recursively checks credentials based on the brains rules."""
        try:
            new_match_list = self.rules[match]
        except KeyError:
            if self.default_rule and match != self.default_rule:
                new_match_list = ('rule:%s' % self.default_rule,)
            else:
                return False

        return self.check(new_match_list, target_dict, cred_dict)

class Brain(object):
    """ Implement Policy Engine """
    
    def __init__(self, conf):
        self.address = conf['address']
        self.port = conf['port']
        self.username= conf['username']
        self.password = conf['password']
        
        
def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return AuthZ(app, conf)
    return auth_filter
