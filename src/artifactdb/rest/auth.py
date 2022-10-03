# pylint: disable=too-many-return-statements  # more readable in check_access_rules()
from typing import Optional
import json
import logging

import asks
import requests
import requests.exceptions

from starlette.requests import Request
from starlette.routing import Match
from fastapi.security import OAuth2AuthorizationCodeBearer
from fastapi.exceptions import HTTPException
from jose.jwt import get_unverified_claims

from artifactdb.config import init_model
from artifactdb.config.cache import CacheConfig
from artifactdb.backend.caches import get_cache
from artifactdb.utils.context import auth_user_context
from artifactdb.identifiers.aid import unpack_id, MalformedID
from artifactdb.backend.components.permissions import NoPermissionFoundError, PermissionsError


class WellKnownException(Exception): pass
# Token related
class UnknownPublicKeyError(Exception): pass
class InvalidTokenSignature(Exception): pass
class TokenError(Exception): pass
class ExpiredTokenError(Exception): pass

DEFAULT_TIMEOUT = 5  # timeout before getting data
DEFAULT_CONNECTION_TIMEOUT = 2  # timeout before establishing connection (before even sending the request)


# Permission checks manipulation

class PermissionCheck(dict):

    def __or__(self, other):
        """
        Return allowing check or False if none of them is allowing
        """
        return (self["allowed"] and self) or (other["allowed"] and other) or False

    def __and__(self, other):
        return self["allowed"] and other["allowed"] and (self + other) or False

    def __add__(self, other):
        """
        Combine allowing permission checks
        """
        assert self["allowed"] and other["allowed"]
        return {"allowed": True, "reason": [self["reason"], other["reason"]]}

# Resource definition

class ResourceError(Exception): pass

class Resource:
    """
    Represent a resource (project/version/file) a user
    is trying to access to.
    """
    def __init__(self, request):
        # all endpoints are formatted the same and use REST-like naming.
        # "project_id" and "version" are used to identify the resource
        # (or "id" if directly accessing a file by its ID)
        params = self.get_path_params(request)
        self.path = request.url.path
        self._project_id = False  # don't use None, it would go up to the bucket level
        self._version = None  # # None: resource is the project itself, not version-specific
        self._path = None  # not used for now, could be when implementing file-specific permissions
        # when accessing a file, id contains project/version
        # note: jobs has "id" formatted as uuid, with 4 "-" chars, so exclude them
        if params.get("id") and params.get("id").count("-") != 4:
            try:
                ids = unpack_id(params.get("id"))
                self._project_id = ids["project_id"]
                self._version = ids["version"]
            except MalformedID as e:
                logging.error("Can't determine project/version from id {}: {}".format(repr(params.get("id")),e))
        else:
            self._project_id = params.get("project_id",False)
            self._version = params.get("version",None)

    def get_path_params(self, request):
        # starlette.Request won't fill path_params until request is fully processed
        # but we're before that, so we need to do that ourselves
        # See: https://github.com/tiangolo/fastapi/issues/861
        routes = request.app.router.routes
        for route in routes:
            match, scope = route.matches(request)
            if match == Match.FULL:
                return scope["path_params"]
        # not found
        return {}

    def __repr__(self):
        klass = "%s" % self.__class__.__name__
        if self._project_id is False:
            return "<%s path=%s>" % (klass,self.path)
        elif self._project_id is None:
            return "<%s all projects, path=%s>" % (klass,self.path)
        elif self._version is None:
            return  "<%s project_id:%s, path=%s>" % (klass,self._project_id,self.path)
        else:
            return "<%s project_id:%s/version:%s, path=%s>" % (klass,self._project_id,self._version,self.path)

    @property
    def project_id(self):
        if self._project_id is False:
            # we couldn't determine what resource this is about
            raise ResourceError("Invalid resource (url={})".format(self.path))
        return self._project_id

    @property
    def version(self):
        return self._version


# Hierarchy of users with gradually increasing permissions

class BaseUser:

    def __init__(self, unixID=None, roles=None, token=None):
        self.unixID = unixID
        self._roles = roles if not roles is None else []
        self.resource = None
        self.distribution_lists = []
        self.active_directory_groups = []
        self.token = {
            "raw": token,
            "claims": token and get_unverified_claims(token),
        }

    @property
    def roles(self):
        raise NotImplementedError()

    def __repr__(self):
        return "<%s:%s roles=%s>" % (self.__class__.__name__,self.unixID,self._roles)


class AnonymousUser(BaseUser):
    """
    Anonymous user has no role, no permissions.
    It can only access 'public' resources.
    """

    @property
    def roles(self):
        # force no roles at all, whatever the value of self._roles
        return []


class AuthenticatedUser(BaseUser):
    """
    Authenticated user has successfully gone through authentication
    and is allowed to have roles.
    """

    @property
    def roles(self):
        return self._roles

    def part_of(self, username_or_dls_or_ad_groups):
        return bool(
            self.unixID in username_or_dls_or_ad_groups or \
            set(self.distribution_lists).intersection(set(username_or_dls_or_ad_groups)) or \
            set(self.active_directory_groups).intersection(set(username_or_dls_or_ad_groups))
        )


class PresignedUser(AnonymousUser):
    pass


class RootUser(AuthenticatedUser):
    pass

# some shortcuts
class BackendUser(RootUser): pass
class AdminUser(RootUser): pass
class God(RootUser): pass

# some default users
backend_user = BackendUser()
admin_user = AdminUser()
root_user = RootUser()
guest = AnonymousUser()
god = God()
authenticated_user = AuthenticatedUser()


class BaseAuthorizer:

    def __init__(self, cfg, permissions_manager, roles=None, access_rules=None, read_eval_time="query", op="or"):
        self.cfg = cfg
        self.permissions_manager = permissions_manager
        self.roles = set(roles if not roles is None else [])  # if empty, there's no role-based checks
        self.read_eval_time = read_eval_time
        if self.roles:
            # only if at least one role is defined we add "admin" (because admin can
            # do anything). If no roles defines, we don't add it because otherwise
            # it would require "admin" role whereas we want *NO* role-based checks
            self.roles.add("admin")
        self.access_rules = access_rules if not access_rules is None else []
        assert op in ("or","and"), "Unknown permission check operator {}".format(repr(op))
        self.op = op

    def __repr__(self):
        return "<{}: roles:{} access_rules:{} read_eval_time:{}>".format(self.__class__.__name__,self.roles,
                                                                         self.access_rules,self.read_eval_time)

    def check_permissions(self, auth_user):
        # any specific roles restrictions?
        roles_check = PermissionCheck(allowed=False,reason="No roles check performed")
        if self.roles:
            roles_check = self.check_roles(auth_user)
            logging.info("Roles check: {}".format(roles_check))

        access_check = PermissionCheck(allowed=False,reason="No access rules check performed")
        if self.permissions_manager and self.access_rules:
            access_check = self.check_access_rules(auth_user)
            logging.info("Access rules check: {}".format(access_check))

        logging.debug("roles_check: %s" % roles_check)
        logging.debug("access_check: %s" % access_check)
        # or/and: check any or all
        check = False
        if self.op == "or":
            check = roles_check | access_check
        else:
            check = roles_check & access_check
        if not check:
            # use XOR __xor__ for PermissionCheck?
            reasons = ";".join([why["reason"] for why in [roles_check,access_check] if not why["allowed"]])
            logging.error("User {} *not* allowed to access {} because: {}".format(auth_user,auth_user.resource,reasons))
            # if anon then unauthorized, else user is auth'd but not allowed
            if isinstance(auth_user,AnonymousUser):
                raise HTTPException(
                    status_code=401,
                    detail="Not authenticated",
                )
            raise HTTPException(
                status_code=403,
                detail="Forbidden, {}".format(reasons)
            )

        logging.info("User {} allowed to access {} because: {}".format(auth_user,auth_user.resource,check["reason"]))

    def check_roles(self, user):
        if isinstance(user,AnonymousUser):
            return PermissionCheck(allowed=False,reason="Anonymous cannot grant role permissions")
        role_ok = self.roles.intersection(set(user.roles))
        if role_ok:
            return PermissionCheck(allowed=True,reason="{} has role {} granted".format(user,role_ok))
        else:
            return PermissionCheck(allowed=False,reason="{} is missing role (one of {})".format(user,self.roles))

    def check_access_rules(self, user):

        if isinstance(user,PresignedUser):
            # no question asked...
            return PermissionCheck(allowed=True,reason="User is using a pre-signed URL")

        assert user.resource, "No resource set, permissions can't be checked"
        # retrieve registered permissions user is trying to access, resolving, ie. exploring
        # further up = project/version, then project, then bucket's root
        try:
            # for now, only allows one access rule
            if len(self.access_rules) > 1:
                raise NotImplementedError("Only one access rule allowed, got: {}".format(repr(self.access_rules)))
            required_access = self.access_rules[0]
            # special case for "read_access", this is handled at query time, using _extra.permissions info
            if required_access == "read_access":
                if self.read_eval_time == "query":
                    return PermissionCheck(allowed=True,reason="Read access will be check during query")
                else:
                    # check read access permissions now. Handle below
                    logging.debug("read_access rules is evaled now (not during query)")

            std_permissions = self.permissions_manager.resolve_permissions(user.resource.project_id,user.resource.version)
            permissions = std_permissions.permissions.to_dict() # inner object

            # required access is something like "read_access", "write_access"
            if not required_access in permissions:
                raise ResourceError("Invalid access, not found: '{}'".format(required_access))
            access = permissions[required_access]

            # if resource is 'public', both anonymous and authenticated users have access
            if access == "public":
                if isinstance(user, (AnonymousUser, AuthenticatedUser)):
                    return PermissionCheck(allowed=True,reason="Public resource")
                else:
                    # we should never get there though...
                    return PermissionCheck(allowed=False,reason="Public resource but user is {}".format(user))

            # 'authenticated' only
            elif access == "authenticated":
                if isinstance(user,AuthenticatedUser):
                    return PermissionCheck(allowed=True,reason="Authenticated user can access resource")
                else:
                    return PermissionCheck(allowed=False,reason="Resource access not allowed to non-authenticated users")

            # 'viewers': user needs to be part of 'viewers', ir 'owners' (if you own a resource, you can view it
            elif access == "viewers":
                if isinstance(user,AuthenticatedUser) and \
                        (user.part_of(permissions.get("viewers",[])) or user.part_of(permissions.get("owners",[]))):
                    which = 'viewers' if user.part_of(permissions.get('viewers', [])) else 'owners'
                    return PermissionCheck(allowed=True,reason="User is part of {}".format(which))
                else:
                    return PermissionCheck(allowed=False,reason="User is not a viewer")
            # finally 'owners', straightforward
            elif access == "owners":
                if isinstance(user,AuthenticatedUser) and user.part_of(permissions.get("owners",[])):
                    return PermissionCheck(allowed=True,reason="User is part of owners")
                else:
                    return PermissionCheck(allowed=False,reason="User is not an owner")

            else:
                # if we get there, something's wrong...
                raise PermissionsError("Unknown access {}".format(repr(access)))

        except (ResourceError, NoPermissionFoundError, PermissionsError) as e:
            logging.error("Can't fetch permissions: {}".format(e))
            return {"allowed": False, "reason": str(e)}

    async def __call__(self, request:Request) -> Optional[str]:
        # at that point, we must have a BaseUser object in auth context,
        # set by artifactdb.rest.middleware
        auth_user = auth_user_context.get()
        self.check_permissions(auth_user)
        return auth_user



class StandardAuthorizer(BaseAuthorizer, OAuth2AuthorizationCodeBearer):
    """
    This authorizer handles both roles ("admin", "uploader", ...) and
    access rules ("public", "authenticated", "read_access", ...). These
    information are part of a BaseUser, found in auth context.

    This authorizer is dedicated to ArtifactDB APIs, where access rules
    are defined according to owners and viewers. There's also a notion
    of inheritance in the permissionns, where they can be defined at
    version, project, or bucket level.

    All permissions checks are done by this authorizer, *except* when
    access rule is "read_access" when read_eval_time=query (default).
    This rule means user is allowed to read data if it has read access.
    This read access is performed directly at query time, for performance
    reason. In other words, "read_access" is postponed until data is
    actually fetched from the index.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args,**kwargs)
        # In case the OpenID server is unstable and we can't fetch the information, we'll use what we have in the cache.
        # If cache is expired and we need to fetch info again, but the server doesn't respond, we use a backup cache
        # that never expires, and gets updated each time we're able to fetch the info. That way we can always start, yes
        # possibly without outdated information, but also unlikely to change that much...
        self.oidc_fetcher = OpenIDFetcher(self.cfg.auth.oidc)
        self.setup_oauth2()

    def setup_oauth2(self):
        OAuth2AuthorizationCodeBearer.__init__(
            self,tokenUrl=self.oidc_fetcher.primary_well_known["token_endpoint"],
            authorizationUrl=self.oidc_fetcher.primary_well_known["authorization_endpoint"],
            refreshUrl=self.oidc_fetcher.primary_well_known["token_endpoint"])


class SimpleAuthorizer(StandardAuthorizer):
    """
    Based on StandardAuthorizer, but doesn't not perform access rules checks
    based on owners/viewers + inheritance. Here, access_rules can be "public"
    or "authenticated".
    """

    def __init__(self, cfg, roles=None, access_rules=None, op="or"):
        # same constructor but we set a dummy permission manager
        super().__init__(cfg,permissions_manager=object(),roles=roles,access_rules=access_rules,op=op)

    def check_access_rules(self, user):
        assert user.resource, "No resource set, permissions can't be checked"
        try:
            # for now, only allows one access rule
            if len(self.access_rules) > 1:
                raise NotImplementedError("Only one access rule allowed, got: {}".format(repr(self.access_rules)))
            access = self.access_rules[0]
            # if resource is 'public', both anonymous and authenticated users have access
            if access == "public":
                if isinstance(user, (AnonymousUser, AuthenticatedUser)):
                    return PermissionCheck(allowed=True,reason="Public resource")
                else:
                    # we should never get there though...
                    return PermissionCheck(allowed=False,reason="Public resource but user is {}".format(user))

            # 'authenticated' only
            elif access == "authenticated":
                if isinstance(user,AuthenticatedUser):
                    return PermissionCheck(allowed=True,reason="Authenticated user can access resource")
                else:
                    return PermissionCheck(allowed=False,reason="Resource access not allowed to non-authenticated users")
            else:
                # if we get there, something's wrong...
                raise PermissionsError("Unknown access {}".format(repr(access)))

        except (ResourceError, NoPermissionFoundError, PermissionsError) as e:
            logging.error("Can't fetch permissions: {}".format(e))
            return {"allowed": False, "reason": str(e)}


class GuestAuthorizer(BaseAuthorizer):
    pass


class OpenIDFetcher:
    """
    Fetch optionally cache .well-knowns, public data key, etc...
    """

    def __init__(self, oidc_cfg):
        """
        `cache_cfg` is a CacheConfig instance. If None, used cached is a CacheoutCacheClient
        with 12h TTL.
        """
        self.cfg = oidc_cfg
        cache_cfg = self.cfg.cache
        if not cache_cfg:
            dcfg = {
                "cache_ttl":43200,
                "backend": {
                    "type":"artifactdb.backend.caches.CacheoutCacheClient"
                }
            }
            cache_cfg = init_model(CacheConfig,dcfg)
        self.cache = get_cache(cache_cfg)

    def fetch_well_known(self, url):
        response = requests.get(url,timeout=DEFAULT_TIMEOUT)
        if response.status_code != 200:
            raise WellKnownException(".well-known URL '{}' not reachable: {} ({})".format(url,response.status_code,response.text))
        return response.json()

    def get_well_known(self, cache_key, fetch_func):
        # query .well-known endpoint to determine token and auth URL for swagger
        backup_cache_key = f"__backup{cache_key}"
        cached = self.cache.get(cache_key)
        if cached:
            return json.loads(cached)

        try:
            well_known = fetch_func()
            # cache that new info, and replace the backup cache as well
            self.cache.set(cache_key,json.dumps(well_known),ttl=self.cache.cache_ttl)
            self.cache.set(backup_cache_key,json.dumps(well_known),ttl=None)  # nevern expires
            return well_known

        except (requests.exceptions.ConnectionError,WellKnownException) as e:
            logging.warning(f"Unable to fetch .well-known information (cache_key={cache_key}): {e}")
            backup_cached = self.cache.get(backup_cache_key)
            if not backup_cached:
                raise WellKnownException("Could not obtain well known information, not even from backup cache")
            logging.info(f".well-known information obtained from backup cache (cache_key={backup_cache_key})")
            return json.loads(backup_cached)

    @property
    def primary_well_known(self):
        def fetcher():
            return self.fetch_well_known(self.cfg.well_known.primary)
        return self.get_well_known("__primary_well_known__",fetcher)

    @property
    def secondary_well_knowns(self):
        # this is for config display purpose
        def fetcher():
            well_knowns = []
            for url in self.cfg.well_known.secondary:
                well_knowns.append(self.fetch_well_known(url))
            return well_knowns
        return self.get_well_known("__secondary_well_knowns__",fetcher)

    async def get_public_key_data(self, kid):
        cache_key = f"__kid_{kid}"
        cached = self.cache.get(cache_key)
        if cached:
            return json.loads(cached)

        logging.info("Fetching .well-known for kid '{}'".format(kid))
        for well_known in [self.primary_well_known] + self.secondary_well_knowns:
            response = await asks.get(well_known["jwks_uri"],
                                      timeout=DEFAULT_TIMEOUT,
                                      connection_timeout=DEFAULT_CONNECTION_TIMEOUT)
            if response.status_code != 200:
                logging.error(f"Unable to fetch public key data from {well_known['jwks_uri']}: {response.text}")
            result = response.json()
            for data in result["keys"]:
                self.cache_public_key_data(data["kid"],data)

        # we fetched them all, we should be good now
        cached = self.cache.get(cache_key)
        if not cached:
            raise UnknownPublicKeyError("Couldn't find kid %s" % kid)
        key_data = json.loads(cached)
        return key_data

    def cache_public_key_data(self, kid, data):
        cache_key = f"__kid_{kid}"
        self.cache.set(cache_key,json.dumps(data),ttl=self.cache.cache_ttl)

