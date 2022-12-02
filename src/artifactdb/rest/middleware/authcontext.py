import re
import json
import logging
import time
import base64
import hashlib
from binascii import Error as DecodeError

import cacheout
import asks  # async requests lib
from jose import jwt, jwk
import jose.exceptions
from jose.utils import base64url_decode

from fastapi.requests import Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import HTTPException

from artifactdb.rest.presign import RedisPresignURLManager, CredentialError
from artifactdb.backend.caches import get_cache
from artifactdb.utils.context import auth_user_context, skip_auth_context
from artifactdb.rest.auth import AdminUser, RootUser, AuthenticatedUser, AnonymousUser, Resource, \
                                 UnknownPublicKeyError, InvalidTokenSignature, ExpiredTokenError, PresignedUser


class IKYSError(Exception): pass


class AuthContextMiddleware:
    """
    Set user (unixID) as a context variable. Value is taken from request object, looking
    for JWT token Headers.

    From there, user is enriched with some Active Directory information, specifying
    which DL or groups the auth user belongs to.
    """

    def __init__(self, auth_conf, authorizer):
        self.auth_cfg = auth_conf
        self.authorizer = authorizer  # used to centralize access to .well-known
        self.dist_list_url_template = self.auth_cfg.ad.dist_list_url_template
        self.active_directory_source = None  # requires custom AD group based permissions
        if auth_conf.distribution_list_cache:
            cache_cfg = auth_conf.distribution_list_cache
            self.dist_list_cache = get_cache(cache_cfg)
        else:
            self.dist_list_cache = None
        self._allowed_client_ids = set(self.auth_cfg.clients.known)
        assert self.allowed_client_ids, "No allowed client IDs defined"
        self.kids = self.auth_cfg.oidc.kids
        # cache certificates (public Key IDS) from Keycloak, so we don't query Keycloak
        # for each token verification.
        if self.kids:
            logging.warning("Predefined kids: {}".format(self.kids))
            for kid,data in self.kids.items():
                self.authorizer.oidc_fetcher.cache_public_key_data(kid,data)
        # cache the whole token for its expiration time if True
        self.cache_tokens = self.auth_cfg.oidc.cache_tokens
        self.token_cache = cacheout.Cache()  # TTL per key cache
        if self.auth_cfg.presign:
            self.presign_manager = RedisPresignURLManager(self.auth_cfg.presign)
        else:
            self.presign_manager = None

    @property
    def allowed_client_ids(self):
        return self._allowed_client_ids

    async def get_public_key_data(self, headers):
        return await self.authorizer.oidc_fetcher.get_public_key_data(headers["kid"])

    def verify_ikys(self, header_value):
        """
        X-API-IKYS-Key is a special API key that is generated based on a secret that the frontend
        knows. IKYS stands for "I Know Your Secret". The purpose of this API key is for local pods
        to talk to the REST API as an admin, without having to have a JWT token for that. The idea is
        because this other pod is deployed in the same namespace as the frontend pod, it can access one
        of the frontend secret. Doing, a JSON document is created with a hash of that secret, then base64
        encoded and passed in that special header. The verification happens here.
        """
        decoded = base64.b64decode(header_value.encode()).decode()
        jdoc = json.loads(decoded)
        if not jdoc.get("type") or jdoc["type"] != "ikys":
            raise IKYSError("Excepting 'ikys' as key type, got {}".format(jdoc.get("type")))
        hfunc = getattr(hashlib,jdoc["hash_function"])
        local_content = open(jdoc["secret_path"]).read()
        local_hash = hfunc(local_content.encode()).hexdigest()
        if local_hash != jdoc["hashed_secret"]:
            raise IKYSError("Given hashed secret doesn't match local computed one")
        # if we get there, all good.

    async def get_dist_lists(self, user):
        response = await asks.get(self.dist_list_url_template.format(user.unixID))
        if response.status_code != 200:
            # can't find DL or groups, but cache that info so we don't keep querying it for nothing
            return []
        else:
            results = response.json()
            # /!\ do we really get all of them? any pagination there?
            dls = {_["email"] for _ in results["response"]["docs"] if _}
            # make the domain optional
            pat = re.compile("(.*)@.*")
            _ = [dls.add(pat.sub("\\1",_)) for _ in list(dls)]
            return list(dls)

    async def get_dist_list_info(self, user):
        # don't even bother fetching info for root (allowed to do anything)
        # or anonymous user (will never match any AD info anyways)
        if isinstance(user, (AnonymousUser, RootUser)):
            return []
        if not self.dist_list_cache:
            return await self.get_dist_lists(user)
        else:
            cache_key = "Dist_list:{}".format(user.unixID)
            if self.dist_list_cache.expired(cache_key):
                dls = await self.get_dist_lists(user)
                self.dist_list_cache.set(cache_key, json.dumps(dls), self.dist_list_cache.cache_ttl)
            # race condition, cache has the key at the beginning of the method,
            # but expired while getting there. Rare. Next call will refresh the cache...
            return set(json.loads(self.dist_list_cache.get(cache_key)))

    async def get_anonymous_user(self, request):  # pylint: disable=unused-argument
        guest = AnonymousUser()
        return guest

    async def get_auth_user(self, request):
        # check we start from fresh. This should *never* happen. If so, we have a serious
        # problem with contextvars...
        assert auth_user_context.get() is None, "Unexpected auth user context (%s)" % auth_user_context.get()
        assert skip_auth_context.get() is False, "Unexpected skip auth context (%s)" % skip_auth_context.get()
        auth_user = None  # from token, ultimately put in context
        token = None
        claims = None
        # get user from headers or query
        if "authorization" in request.headers:

            if not "Bearer" in request.headers["authorization"]:
                auth_method = request.headers["authorization"].split()[0]
                logging.warning("Unsupported authorization, expected 'Bearer', " + \
                               f"""got {auth_method!r}, ignoring""")
                return AnonymousUser()

            token = request.headers["authorization"].replace("Bearer","").strip()
            claims = await self.check_token(token)

            # at that point, claims are legit and can be trusted
            assert claims
            client_id = claims.get("client_id") or claims.get("clientId")
            # /!\ with almight tokens, username is always taken from the preferred_username field
            unix_id = claims["preferred_username"]

            if not unix_id:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid token, no preferred_name set"
                )

            if "resource_access" in claims:
                # roles specific for current API
                if self.auth_cfg.oidc.client_id in claims["resource_access"]:
                    roles = claims["resource_access"][self.auth_cfg.oidc.client_id]["roles"]
                # roles defined in service account (eg. GPSA)
                elif client_id in claims["resource_access"]:
                    roles = claims["resource_access"][client_id]["roles"]
                else:
                    roles = []
                if "admin" in roles:
                    logging.debug("User {} is admin".format(unix_id))
                    auth_user = AdminUser(unixID=unix_id,roles=roles)
                else:
                    # authenticated user with roles from Keycloak
                    auth_user = AuthenticatedUser(unixID=unix_id,roles=roles)
            else:
                # authenticated user without roles
                auth_user = AuthenticatedUser(unixID=unix_id)
        elif "x-api-ikys-key" in request.headers:
            try:
                self.verify_ikys(request.headers["x-api-ikys-key"])
                auth_user = AdminUser(unixID="ikys-challenger",roles=["admin"])
                logging.debug(f"IKYS API Key provided, injecting user {auth_user} in context")
            except (DecodeError, json.JSONDecodeError, FileNotFoundError, KeyError,
                    AttributeError, IKYSError) as e:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid IKYS key: {e}",
                )
        else:
            auth_user = AnonymousUser()

        assert auth_user
        # enrich with what we checked before
        auth_user.token["raw"] = token
        auth_user.token["claims"] = claims

        # check for presign URL information, adjust auth context if so
        if self.presign_manager:
            auth_user = self.check_presigned_url(request,auth_user)

        return auth_user

    def check_presigned_url(self, request: Request,auth_user):
        try:

            signature = self.presign_manager.check(request)
            if signature:
                # signature verified and valid, change auth to "presigned"
                presign_user = PresignedUser()
                presign_user.__dict__.update(auth_user.__dict__)
                logging.info(f"User {auth_user} converted to presigned-user {presign_user}")
                return presign_user
            else:
                # no signature, nothing to do
                return auth_user

        except CredentialError as e:
            raise HTTPException(
                status_code=403,
                detail="Forbidden, {}".format(str(e)),
            )

    async def set_auth_user_context(self, request: Request, call_next):
        try:
            if self.auth_cfg.enabled:
                auth_user = await self.get_auth_user(request)
            else:
                auth_user = await self.get_anonymous_user(request)
        except HTTPException as e:
            # re-wrap exception as a Response, as middleware can only return responses
            return JSONResponse(status_code=e.status_code,
                                content={"reason": e.detail,"status": "error"},
                                headers=e.headers)

        auth_user.resource = Resource(request)
        if auth_user.resource.path != "/":  # limit logging
            logging.info("Set user context for {}, accessing {}".format(auth_user,auth_user.resource))

        ctx = auth_user_context.set(auth_user)
        dls = await self.get_dist_list_info(auth_user)
        auth_user.distribution_lists = dls

        if self.active_directory_source:
            ad_groups = await self.active_directory_source.get_ad_groups(auth_user)
        else:
            ad_groups = []
        auth_user.active_directory_groups = ad_groups

        if not isinstance(auth_user,AnonymousUser):
            logging.info(f"User {auth_user.unixID}, AD groups: {auth_user.active_directory_groups}")

        # process the actual request
        response = await call_next(request)
        if ctx:
            # Test: make sure it didn't change
            ctx_auth_user = auth_user_context.get()
            assert auth_user == ctx_auth_user, "auth_user: %s, ctx: %s" % (auth_user,ctx_auth_user)
            auth_user_context.reset(ctx)
        # make sure skip_auth_context is False when leaving the request
        # note it should never (can't) be other than False, because the request context is defined here, in that
        # method, and since skip_auth_context isn't used there, it's not changed
        assert skip_auth_context.get() is False, "skip_auth_context left as True while ending request"

        return response

    async def check_token_signature(self, token):
        headers = jwt.get_unverified_headers(token)
        # use that kid to get the public key from keycloak
        key_data = await self.get_public_key_data(headers)
        # construct the public key
        public_key = jwk.construct(key_data)
        # get the last two sections of the token,
        # message and signature (encoded in base64)
        message, encoded_signature = str(token).rsplit('.', 1)
        # decode the signature
        decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))
        # verify the signature
        if not public_key.verify(message.encode("utf8"), decoded_signature):
            raise InvalidTokenSignature("invalid signature")

    def check_token_expiration(self, token):
        claims = jwt.get_unverified_claims(token)
        # since we passed the verification, we can now safely
        # use the unverified claims
        # additionally we can verify the token expiration
        ttl = claims['exp'] - time.time()
        if ttl <= 0:  # time() returns epoch (UTC)
            # if ttl is < 0 , it means by the time we get there the token expired...
            # we don't cache it, expiration error will be caught later.
            raise ExpiredTokenError("token has expired")
        return ttl

    async def check_token(self, token):
        try:
            claims = jwt.get_unverified_claims(token)
            if not "jti" in claims:
                raise jose.exceptions.JWTError("missing 'jti' field")
        except jose.exceptions.JWTError as e:
            reason = "malformed token claims: {}".format(e)
            raise HTTPException(
                status_code=400,
                detail="Invalid token, {}".format(reason),
                headers={"WWW-Authenticate": "Bearer"},
            )

        cached_jti = self.token_cache.get(claims["jti"])
        if cached_jti:
            logging.debug("Token jti:%s still valid for %ss" % (claims["jti"],claims["exp"]-time.time()))
            return claims

        # get the kid from the headers prior to verification
        try:
            headers = jwt.get_unverified_headers(token)
        except jose.exceptions.JWTError:
            reason = "malformed token headers: {}".format(e)
            raise HTTPException(
                status_code=400,
                detail="Invalid token, {}".format(reason),
                headers={"WWW-Authenticate": "Bearer"},
            )

        try:
            await self.check_token_signature(token)
        except UnknownPublicKeyError as e:
            logging.exception(e)
            reason = "unknown public key '{}' ({}): {}".format(headers.get("kid"),id(self),e)
            raise HTTPException(
                status_code=400,
                detail="Invalid token, {}".format(reason),
                headers={"WWW-Authenticate": "Bearer"},
            )
        except InvalidTokenSignature as e:
            reason = "signature verification failed"
            raise HTTPException(
                status_code=400,
                detail="Invalid token, {}".format(reason),
                headers={"WWW-Authenticate": "Bearer"},
            )

        try:
            ttl = self.check_token_expiration(token)
        except ExpiredTokenError:
            reason = "expired"
            raise HTTPException(
                status_code=400,
                detail="Invalid token, {}".format(reason),
                headers={"WWW-Authenticate": "Bearer"},
            )

        # the rest is application-specific, we could check
        # - clientID
        # - roles
        # - email,
        # - etc..
        azp = claims.get("azp")
        if not azp:
            reason = "Can't find 'azp'"
            raise HTTPException(
                status_code=400,
                detail="Invalid token, {}".format(reason),
                headers={"WWW-Authenticate": "Bearer"},
            )

        # this one only exists if it's a service account
        # keycloak token will set azp == client_id in that case.
        # but in almighty token they may be different
        client_id = claims.get("client_id") or claims.get("clientId")
        if not client_id:
            logging.debug("No client_id, take it from azp ('{}')".format(azp))
            client_id = azp  # we'll take it from there if not a service account
        else:
            if client_id != azp:
                logging.debug("client_id '{}' ".format(client_id) + "and azp '{}' ".format(azp) \
                            + "are different, client_id has precedence")
            else:
                logging.debug("client_id and azp are the same: {}".format(client_id))

        # some "known" clients can come from external resource (namely github)
        # so we need to include them dynamically&
        known_client_ids = set(self.allowed_client_ids)
        if client_id not in known_client_ids:
            reason = "unknown client_id"
            raise HTTPException(
                status_code=400,
                detail="Invalid token, {}".format(reason),
                headers={"WWW-Authenticate": "Bearer"},
            )

        # sanity check for roles, if any
        if "resource_access" in claims:
            # roles are defined in gCustoms and found in token as:
            # "resource_access": {
            #     "resultsdb": {
            #     "roles": ["admin"]  # roles
            #     }
            # }
            forbidden = True
            reason = None
            if client_id in claims["resource_access"] and "roles" not in claims["resource_access"][client_id]:
                reason = "malformed roles"
            else:
                forbidden = False

            if forbidden:
                raise HTTPException(
                    status_code=403,
                    detail="Forbidden, {}".format(reason),
                )

        # So far so good
        if self.cache_tokens:
            # cache it with expiration (ttl from now)
            logging.debug("Caching token jti:%s for %ss" % (claims["jti"],ttl))
            self.token_cache.set(claims["jti"],1,ttl=ttl)

        return claims
