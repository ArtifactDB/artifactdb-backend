from aumbry import Attr
from .utils import PrintableYamlConfig
from .cache import CacheConfig


class WellKnownConfig(PrintableYamlConfig):
    __mapping__ = {
        "primary": Attr("primary",str),
        "secondary": Attr("secondary",list),
    }
    # first well known is the principal one, used in Swagger
    primary = None
    # other are used when checking token signature, in addition to the primary ones
    secondary = []

class OIDCConfig(PrintableYamlConfig):
    __mapping__ = {
        'client_id': Attr('client_id',str),
        'well_known': Attr("well_known",WellKnownConfig),
        "cache": Attr("cache",CacheConfig),
        'kids': Attr('kids',dict),
        'cache_tokens': Attr('cache_tokens',bool),
    }
    client_id = None # client ID used to auth in Swagger
    cache = CacheConfig()
    # cache tokens based on "jti" field (token ID) and "exp" (token ttl)
    cache_tokens = True
    # kid (for public keys) are fetched from Keycloak
    # but we can define our own here (for tests purpose)
    # Ex:
    #   from jose import jwt, jwk
    #   klass = jwk.get_key("HS256")
    #   key = klass("<secret>","HS256").to_dict()
    #   key["k"] = key["k"].decode() # or construct() doesn't work
    #   public_key = jwk.construct(key)
    # Token can be generated using the same secret
    #   token = jwt.encode({'some': 'payload'}, "<secret>", algorithm='HS256', headers={'kid': 'dink'})
    kids = {}


class ActiveDirectoryConfig(PrintableYamlConfig):
    __mapping__ = {
        "dist_list_url_template": Attr("dist_list_url_template", str),
        "ttl": Attr("ttl", int)
    }

    dist_list_url_template = None  # no distrib-list support by default
    ttl = 24*60*60  # a whole day

# Known clients
class AuthClients(PrintableYamlConfig):
    __mapping__ = {
        'known': Attr('known', list),
    }
    known = []


# Main auth config
class AuthConfigBase(PrintableYamlConfig):
    __mapping__ = {
        'enabled': Attr('enabled',bool),
        'app_name': Attr('app_name',str),
        'oidc': Attr('oidc',OIDCConfig),
        'clients': Attr('clients', AuthClients),
        'presign': Attr('presign',dict),
        # Own API service account to interact with Keycloak, if necessary
        'service_account': Attr("service_account",dict),
        # test only
        'test_client': Attr('test_client', dict),
        # anything related to AD, additional user info
        'ad': Attr('ad',ActiveDirectoryConfig),
        'distribution_list_cache': Attr('distribution_list_cache', dict),
    }
    # master switch
    enabled = True  # disable it means no authorization, but authentication (login via Keycloak) is still required
    app_name = None  # human read

    oidc = OIDCConfig()
    clients = AuthClients()
    # presign conf
    presign = {}
    # keycloak helper/client
    service_account = None
    # nothing by default
    test_client = {}
    ad = ActiveDirectoryConfig()
    distribution_list_cache = None

