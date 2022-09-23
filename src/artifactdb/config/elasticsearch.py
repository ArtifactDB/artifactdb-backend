from aumbry import Attr
from .utils import init_model, PrintableYamlConfig
from .switches import Switch


class ElasticsearchRepositoryConfig(PrintableYamlConfig):
    __mapping__ = {
        "name": Attr("name",str),
        "settings": Attr("settings",dict),
        "auto_create": Attr("auto_create",bool),
    }

    name = None
    settings = {}
    auto_create = False


class ElasticsearchSnapshotConfig(PrintableYamlConfig):
    __mapping__ = {
        "repository": Attr("repository", ElasticsearchRepositoryConfig),
        "poll_interval": Attr("poll_interval",int),
        "max_retry": Attr("max_retry",int),
        "prefix": Attr("prefix",str),
    }

    # when waiting for a snapshot to complete, how should we wait
    # before check snapshot status again? in seconds
    poll_interval = 10
    # how many times should we poll in total?
    max_retry = 30
    # set by backend manager during init (ES manager doesn't have access to GPRN config,
    # and snapshot name prefix is derived from GPRN)
    prefix = None


class ElasticsearchManagerConfig(PrintableYamlConfig):
    __mapping__ = {
        "uri": Attr("uri", str),
        "multi_index_search_pattern": Attr("multi_index_search_pattern", str),
        "ref": Attr("ref", str),
        "clients": Attr("clients", dict),
        'snapshot': Attr('snapshot', ElasticsearchSnapshotConfig),
    }
    uri = None
    multi_index_search_pattern = None
    clients = {}  # per-alias => ElasticsearchConfig dict
    ref = None

    def __iter__(self, *args, **kwargs):
        yield from self.clients.keys()

    def get(self, schema_version):
        conf = self.clients[schema_version]
        esconf = init_model(ElasticsearchConfig,conf)
        return esconf


# Main entry point: frontend/backend definitions
class ElasticMainConfig(PrintableYamlConfig):
    __mapping__ = {
        'frontend': Attr('_frontend', ElasticsearchManagerConfig),
        'backend': Attr('_backend', ElasticsearchManagerConfig),
        'scroll': Attr('scroll', dict),
        'switch': Attr('switch', Switch),
        'fix_orphan_links': Attr('fix_orphan_links',bool),
        'auto_create_aliases': Attr('auto_create_aliases',bool),
        'auto_sync_aliases': Attr('auto_sync_aliases',bool),
        'create_default_client': Attr('create_default_client',bool),
    }

    _frontend = None
    _backend = None
    fix_orphan_links = False
    # Auto-create aliases when they are missing (recommended)
    auto_create_aliases = True
    # Auto-sync aliases back to correct index declared in backend,f they're pointing
    # to the wrong index (not recommended, this situation can be normal when full re-indexing happens)
    auto_sync_aliases = False
    # if no clients defined at all, should a default/dummy be created to make it functional at minimum
    create_default_client = True
    switch = Switch()

    def merge_missing_frontend_fields(self):
        """
        Indices and models information is preferrably stored in backend section,
        while the frontend usually defined aliases, to limit duplication in config.
        This method is used to propagate necessary fields from backend to frontend,
        when these are missing.
        """
        # complete with models info if none are defined in frontend section
        for name in self._frontend.clients:
            client = self._frontend.clients[name]
            backend_model = self._backend.clients[name].get("model")
            if backend_model and not "model" in client:
                client["model"] = backend_model
            backend_dynamic = self._backend.clients[name].get("dynamic")
            if backend_dynamic and not "dynamic" in client:
                client["dynamic"] = backend_dynamic

    @property
    def frontend(self):
        assert not self._frontend.ref, "`ref` is frontend section is not supported"
        if not self._backend.ref:
            # if backend has its own section defined (ie. not pointing to frontend with a `ref`)
            # we may need to propagate some fields in the frontend (models)
            self.merge_missing_frontend_fields()
        return self._frontend

    @property
    def backend(self):
        ref = self._backend.ref
        if ref:
            return getattr(self,ref)
        else:
            return self._backend


class SchemaRouteConfig(PrintableYamlConfig):
    __mapping__ = {
        "aliases": Attr("aliases",list),
        "versions": Attr("versions",list),
    }
    # document select a schema clients
    aliases = []
    versions = []


class RouterConfig(PrintableYamlConfig):
    __mapping__ = {
        "schema": Attr("schema",SchemaRouteConfig),
    }
    schema = SchemaRouteConfig()


class SchemaBasedDynamicModelConfig(PrintableYamlConfig):
    __mapping__ = {
        "alias": Attr("alias",str),
    }

class DynamicModelConfig(PrintableYamlConfig):
    __mapping__ = {
        "schema": Attr("schema",SchemaBasedDynamicModelConfig)
    }
    schema = SchemaBasedDynamicModelConfig()


# ES client config (handling one index)
class ElasticsearchConfig(PrintableYamlConfig):
    __mapping__ = {
        'uri': Attr('uri', str),
        'index': Attr('index', str),
        'alias': Attr('alias', str),
        'model': Attr('model', str),
        'dynamic': Attr('dynamic', DynamicModelConfig),
        'default_if_no_schema': Attr('default_if_no_schema',bool),
        'default_size': Attr('default_size',int),
        'default_returned_results': Attr('default_returned_results',int),
        'custom_scroll_threshold': Attr('custom_scroll_threshold',int),
        'max_returned_results': Attr('max_returned_results',int),
        'extra_total_fields_limit_percent': Attr('extra_total_fields_limit_percent',float),
        'max_total_fields_limit': Attr('max_total_fields_limit',int),
        'min_total_fields_limit': Attr('min_total_fields_limit',int),
        'index_settings': Attr('index_settings',dict),
        'router': Attr("router",RouterConfig),
        'client_class': Attr("client_class",str),
    }
    uri = None
    index = None
    alias = None
    model = None
    default_if_no_schema = False
    default_size = 50  # number of results per default in one request for a given project
    default_returned_results = 50 # numbers of results per scroll, returned in a /search
    custom_scroll_threshold = 10000  # from/size can't handle more than that, if >, then use ES scroll
    max_returned_results = default_returned_results * 10 # max number of records in single query using /search with size param
    extra_total_fields_limit_percent = 0.5
    max_total_fields_limit = 2000
    min_total_fields_limit = 1000
    index_settings = {}
    router = RouterConfig()
    dynamic = DynamicModelConfig()
    client_class = "elasticsearch.client.Elasticsearch"


