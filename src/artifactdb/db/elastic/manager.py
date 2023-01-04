# pylint: disable=unused-import  # keep common classes available to client imports
import os
import logging
import base64
import copy
from asyncio import sleep as aiosleep
from functools import wraps, partial

from elasticsearch import NotFoundError, RequestError
from elasticsearch_dsl import Search, Q, connections, Keyword, Text, Document
import jsonpath_rw_ext

from artifactdb.rest.auth import RootUser, BaseUser
from artifactdb.db.schema import SchemaClient,SchemaClientManager
from artifactdb.config.elasticsearch import ElasticsearchConfig, ElasticsearchManagerConfig
from artifactdb.utils.context import auth_user_context, skip_auth_context, es_default_index_context, es_switch_context
from artifactdb.identifiers.gprn import generate as generate_gprn
from artifactdb.identifiers.aid import unpack_id
from .client import ElasticClient
from .models import ModelProviderManager
from .scrollers import CustomScrollError
from .utils import authorize_query, parse_q, parse_fields, escape_query_param
from . import NotAllowedException, NoMoreResultsException, DEFAULT_SCROLL, DataInconsistencyException, \
              SnapshotInProgress, SnapshotFailure, SnapshotAlreadyExists


class IndexNamingConventionError(Exception): pass
class InvalidIndexNameError(Exception): pass
class NoClientDefinedError(Exception): pass


###################################################
## /!\ AUTHENTICATION/AUTHORIZATION FUNCTION !!!  #
## THINK TWICE BEFORE MODIFYING THEM !!!          #
###################################################
# TODO: actually... this is not completely true, as
# some of the authorization steps are performed during
# queries. duplication ?

def filter_hits_for_viewers(hits, auth_user):
    if isinstance(auth_user, RootUser):
        # this context was programmatically set, it's not coming from
        # a token or a requests
        logging.debug("Root user in context: {}".format(auth_user))
        return hits
    else:
        assert isinstance(auth_user,BaseUser), "Unexpected auth_user type: {}".format(type(auth_user))

    # if user, or any DLs/groups she's in, is found in viewers, it's allowed
    dls = set(auth_user.distribution_lists)
    if auth_user.unixID:  # anonymous unidID is None
        dls.add(auth_user.unixID)

    def get_viewers(hit):
        doc = {}
        if isinstance(hit,dict):
            # Raw ES result
            doc = hit["_source"]
        else:
            # DSL model object
            doc = hit.to_dict()
        # TODO: check "read_access" for the rule, here, read_access=viewers is the
        # only implementation available
        owners = set(doc.get("_extra",{}).get("permissions",{}).get("owners",[]))
        viewers = set(doc.get("_extra",{}).get("permissions",{}).get("viewers",[]))
        return viewers.union(owners)

    filtered = []
    for hit in hits:
        viewers = get_viewers(hit)
        if viewers:
            allowed = dls.intersection(viewers)
            if allowed:
                logging.info("Resource allowed for user '{}' because {} found in owners/viewers".format(auth_user,allowed))
                filtered.append(hit)
            else:
                # filtered out, next
                continue
        else:
            logging.warning("Document {} has no associated viewers (owners or viewers), considered as 'hidden'".format(hit["_id"]))

    return filtered


def authfilter(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth_user = auth_user_context.get()
        if not auth_user:
            raise NotAllowedException("No user context found")

        results = func(*args, **kwargs)
        if not results:
            return

        if not results:
            # we had results before (see check above), now nothing, that's a plain unauthorized
            raise NotAllowedException("Resource not allowed for given user")

        return results

    return wrapper

###################


class ElasticManager:

    def __init__(self, conf_es, es_section, scroll_cfg, switch_cfg=None, gprn_cfg=None, schema_cfg=None):
        self.clients = {}
        self.schema_manager = None
        self.es_section = es_section  # typically "frontend" or "backend"
        self.global_cfg = conf_es  # contains all sections
        self.cfg = getattr(conf_es,es_section)
        self.scroll_cfg = scroll_cfg
        self.switch_cfg = switch_cfg
        self.gprn_cfg = gprn_cfg
        self.schema_cfg = schema_cfg
        self._contexts = {}

        if scroll_cfg and scroll_cfg["backend"]["type"] != "redis":
            raise ValueError("Invalid scroll backend type, only 'redis' supported for now")

        # make sure we have at least one client defined (ie. an index)
        self.ensure_es_clients()
        # make sure all uri are the same (because we do multi-index search on the same server)
        self.default_version_if_no_schema = None
        self.latest_model_version = ""

        self.schema_manager = SchemaClientManager(self.schema_cfg)
        self.model_provider = ModelProviderManager(self)

        # get default version + latest version
        # schema_version is more like a ES client name/alias
        for schema_version in self.cfg.clients:
            if schema_version > self.latest_model_version:
                self.latest_model_version = schema_version
            client_config = self.cfg.get(schema_version)
            # if the client config doesn't specify a ES URI, we propagate
            # the URI from the main section config itself (URI is usually
            # shared across all clients, but we can still customize it)
            if not client_config.uri:
                client_config.uri = self.cfg.uri
            client_alias = schema_version  # semantic issue, it used to be an schema versio, it's more like an alias now
            self.clients[schema_version] = ElasticClient(client_alias,client_config,
                                                         scroll_cfg=self.scroll_cfg,
                                                         model_provider=self.model_provider)
            if client_config.default_if_no_schema:
                self.default_version_if_no_schema = schema_version
        if self.default_version_if_no_schema is None and self.cfg.clients:
            # no specific client asssigned to default, picking the last one
            self.default_version_if_no_schema = sorted(self.cfg.clients)[-1]
        logging.info("Default model version (if no $schema found at all): %s",self.default_version_if_no_schema)

        # we need an elasticsearch client for multi index search, just get it from latest model version
        # (note we made sure before that all clients have the same URI so it doesn't matter which one
        # we pick). We copy to client to have a different ref: the clients in self.clients must not change,
        # as they are used for indexing and routing. But switch() will modify self.es_client to match different sets of
        # indices, which without a copy, would change self.clients[self.latest_model_version] by reference.
        self.es_client = copy.copy(self.clients[self.latest_model_version])
        self.schema_map = {}  # cache: $schema value -> model version (eg. v1, v2)
        self.find_aliases()

        # index "star" = multi index search
        if self.cfg.multi_index_search_pattern:
            self._index_name = self.cfg.multi_index_search_pattern
        else:
            # combine index names to perform multi-index search
            all_index_names = [client.index_name for client in self.clients.values()]
            self._index_name = ",".join(all_index_names)
        logging.info("Search will be performed on '%s'" % self.index_name)

        # keep track of field containing a sub-type (text => keyword)
        self.resolved_fields = {}

    def ensure_es_clients(self):
        if not self.cfg.clients:
            if self.global_cfg.create_default_client:
                client_alias = "default"
                assert self.cfg.multi_index_search_pattern, "Creating a default client requires " + \
                        "`multi_index_search_pattern` to be set (the default index name is derived from it)"
                index_name = self.cfg.multi_index_search_pattern.split(",")[0].strip()
                index_name = index_name.replace("*","default")
                default_cfg = {
                    "model": "artifactdb.db.elastic.models.ArtifactDBDocumentMinimal",
                    "index": index_name,
                    "default_if_no_schema": True,
                }
                self.cfg.clients[client_alias] = default_cfg
                logging.info(f"Creating a {self.es_section} default client with configuration: {self.cfg.clients[client_alias]}")
            else:
                # no clients (ie. no model/index defined), and not allowed to use a default, minimal one.
                # but we still need to have a ES client so the API doesn't crash. We just want it to return
                # nothing. We use a dummy client for that purpose.
                default_cfg = {
                    "model": "artifactdb.db.elastic.models.ArtifactDBDocumentDummy",
                    "client_class": "artifactdb.db.elastic.client.DummyClient",
                    "default_if_no_schema": True,
                }
                self.cfg.clients["dummy"] = default_cfg

    def switch(self, alias):
        # first reset context if one was previously set
        if self._contexts:
            es_default_index_context.reset(self._contexts.pop("indices_ctx"))
            es_switch_context.reset(self._contexts.pop("switch_ctx"))
            self.es_client = copy.copy(self.clients[self.latest_model_version])
            assert not self._contexts  # nothing left we didn't think about
        # None means we reset context, so proceed further only if alias is set to something
        if not alias is None:
            indices = self.switch_cfg.contexts[alias]
            switch_ctx = es_switch_context.set(alias)
            indices_ctx = es_default_index_context.set(indices)
            self.es_client.index_name = ",".join(indices)
            self._contexts = {"switch_ctx": switch_ctx, "indices_ctx": indices_ctx}

    def create_repository(self, settings, name=None):
        """
        Create a snapshop repository if it doesn't exists yet.
        Params are passed to self.es_client.snapshot.create_repository(...).
        """
        repo_name = name or self.cfg.snapshot.repository.name
        try:
            self.get_repository(repo_name)
        except NotFoundError:
            self.es_client.client.snapshot.create_repository(repo_name,settings)
            return self.get_repository(repo_name)

    def get_repository(self, name=None):
        repo_name = name or self.cfg.snapshot.repository.name
        return self.es_client.client.snapshot.get_repository(repo_name)

    def delete_repository(self, name=None):
        repo_name = name or self.cfg.snapshot.repository.name
        return self.es_client.client.snapshot.delete_repository(repo_name)

    async def create_snapshot(self, snapshot_name:str, indices:list, check="success"):
        """
        Create a snapshot `snapshot_name` of `indices`
        See `check` in get_snapshot() for more: if not False, this is a blocking call,
        returning only when the snapshot process is over.
        """
        #TODO: concurrent snapshot usually not allowed... how to deal with that?
        repo_name = self.cfg.snapshot.repository.name
        if isinstance(indices,str):
            indices = [indices]
        try:
            #TODO: we could allow custom metadata, see:
            # https://www.elastic.co/guide/en/elasticsearch/reference/current/create-snapshot-api.html
            res = self.es_client.client.snapshot.create(repo_name,snapshot_name,
                                                        {"indices": ",".join(indices)})
            if res != {"accepted": True}:
                raise SnapshotFailure(res)
        except RequestError as e:
            if e.error == "invalid_snapshot_name_exception" \
                    and "snapshot with the same name already exists" in e.info["error"]["reason"]:
                raise SnapshotAlreadyExists(snapshot_name)
            raise
        # obtain snapshot info
        res = self.get_snapshot(snapshot_name)
        if check is False:
            return res
        else:
            for _ in range(self.cfg.snapshot.max_retry):
                try:
                    res = self.get_snapshot(snapshot_name,check=check)
                    return res
                except SnapshotInProgress:
                    logging.debug(f"Snapshot in progress: {snapshot_name}")
                    await aiosleep(self.cfg.snapshot.poll_interval)

        return res

    def list_snapshots(self):
        repo_name = self.cfg.snapshot.repository.name
        prefix = "{}*".format(self.es_snapshot_gprn)
        #TODO: pagination/scroll?
        res = self.es_client.client.snapshot.get(repo_name,prefix)
        return res

    def get_snapshot(self, snapshot_name:str, check=False):
        """
        Return snapshot information. `check` can be used to check the snapshot status:
        - False: no check, return snapshot information
        - "done": check if snapshot is done, success or failure. A SnapshotInProgress exception
          is raised if not done yet.
        - "success": same as "done" but explictely check for success state. A SnapshotInProgress exception
          is raised if still in progress, and a SnapshotFailure exception is raised if it failed.
        """
        repo_name = self.cfg.snapshot.repository.name
        res = self.es_client.client.snapshot.get(repo_name,snapshot_name)
        assert "snapshots" in res and len(res["snapshots"]) == 1, "More than one snapshot found"
        snapshot = res["snapshots"][0]
        if check is False:
            return snapshot
        if check in ("done","success"):
            if snapshot["state"] == "IN_PROGRESS":
                raise SnapshotInProgress(snapshot_name)
            if check == "success" and not snapshot["state"] == "SUCCESS":
                raise SnapshotFailure(snapshot_name)
            return snapshot
        else:
            raise ValueError(f"Invalid value for parameter 'check': {check}")

    def delete_snapshot(self, snapshot_name:str):
        repo_name = self.cfg.snapshot.repository.name
        #TODO: iirc for big snapshot, it's not instantly done and we need to check the completion
        return self.es_client.client.snapshot.delete(repo_name,snapshot_name)

    @property
    def es_snapshot_gprn(self):
        assert self.gprn_cfg, "No GPRN config found, unable to generate ES snapshot GPRN prefix"
        return generate_gprn({
            "environment": self.gprn_cfg.environment,
            "service": self.gprn_cfg.service,
            "placeholder": None,
            "type-id": "backup",
        })

    @property
    def index_name(self):
        """
        Return default index name as set in the configutation from multi-index
        search pattern, or from a context variable named "es_default_index_context"
        """
        index_from_context = es_default_index_context.get()
        return index_from_context or self._index_name

    @property
    def active_indices(self):
        return [cl.index_name for cl in self.clients.values() if cl.index_name]

    def check_models(self):
        checks = {}
        for name,client in self.clients.items():
            try:
                checks[name] = client.check() or []
            except NotFoundError:
                checks[name] = None

        return checks

    def find_aliases(self):
        """
        Maps index name with alias name
        """
        self.aliases = {}
        info = self.es_client.client.indices.get("*")
        for name in info:
            for client in self.clients.values():
                if client.index_name in info[name]["aliases"]:
                    self.aliases[name] = client.index_name
        logging.info("Aliases found (index => alias): {}".format(self.aliases))

    def resolve_field(self, dot_field_name, sub_type):
        switch = es_switch_context.get()
        cache_key = (switch,dot_field_name,sub_type)
        if cache_key not in self.resolved_fields:
            # query ES mapping to fetch field mapping definition
            # if field has multiple mappings (sub-type) due to dynamic:true,
            # there will be a "fields" witht the mapping for the sub-type
            response = self.es_client.client.indices.get_field_mapping(dot_field_name,index=self.index_name)
            sub_field_name = dot_field_name  # no resolution by default
            for result in response.values():
                if result["mappings"]:
                    mappings = result["mappings"][dot_field_name]
                    field_name = dot_field_name.split(".")[-1]
                    if "fields" in mappings["mapping"][field_name]:
                        sub_field = mappings["mapping"][field_name]["fields"]
                        # is this sub-field pointing to the sub-type definition we're looking for?
                        found = False
                        for sub_name,sub_mapping in sub_field.items():
                            if sub_type in sub_mapping["type"]:
                                sub_field_name = f"{dot_field_name}.{sub_name}"
                                found = True
                                break
                        if found:
                            logging.debug(f"Resolved field '{dot_field_name}' as '{sub_field_name}' with sub-type '{sub_type}'")
                            break
            # either cache what we found or original field
            self.resolved_fields[cache_key] = sub_field_name

        return self.resolved_fields[cache_key]

    def init(self, purge=False):
        """
        Initialize indices for each registered clients. Unless purge is True, no index is deleted if
        it already exists
        """
        for es_client in self.clients.values():
            es_client.init(purge=purge)
        if hasattr(self.cfg,"snapshot") and self.cfg.snapshot:
            self.init_snapshot()

    def init_snapshot(self):
        repo_name = self.cfg.snapshot.repository.name
        assert repo_name
        if self.cfg.snapshot.repository.auto_create:
            repo_cfg = self.cfg.snapshot.repository.settings
            try:
                repo = self.get_repository()
            except NotFoundError:
                logging.info(f"Auto-creating snapshot repository {repo_name}: {repo_cfg}")
                return self.create_repository(repo_cfg)
        else:
            # this will ensure, no matter what, that we have a working repo
            # if it's been declared in config
            repo = self.get_repository()

        logging.debug(f"Found snapshot repository: {repo}")
        return repo

    def get_client_for_model(self, model_version):
        """
        Retuns ES client matching model version (ES alias)
        """
        try:
            es_client = self.clients[model_version]
        except KeyError:
            logging.warning(f"Model '{model_version}' doesn't exist, returning default client")
            es_client = self.clients[self.default_version_if_no_schema]

        return es_client

    def get_client_for_document(self, doc):
        """
        Select appropriate Elasticsearch model matching given
        schema string. There's an implicit and explicit mapping:
        - implicit: the ES alias from `es` config section  matches the schema alias
          from `schema` section
        - explicit: `es` section can define a `schema` sub-section with explicit matching.
        """
        try:
            schema_str = doc["$schema"]
        except KeyError:
            return self.clients[self.default_version_if_no_schema]

        if schema_str is None:
            # $schema field exists, but not set, so using default client
            return self.clients[self.default_version_if_no_schema]

        # try to find in the cache
        es_client = self.schema_map.get(schema_str)
        if es_client:
            return es_client

        # no luck with the cache.
        name,version_json = schema_str.split("/")
        version = version_json.replace(".json","")
        schema_client = self.schema_manager.get_client_for_document(name,version_json)

        # 1. check if the doc matches a schema client alias
        if schema_client:
            for es_client in self.clients.values():
                if schema_client.alias in es_client.cfg.router.schema.aliases:
                    logging.debug(f"Document with $schema {schema_str} matches router's schema alias {schema_client.alias}, " + \
                                  f"using ES client {es_client}")
                    self.schema_map[schema_str] = es_client
                    return es_client
        else:
            logging.warning(f"No schema client found to handle document with $schema {schema_str}, " + \
                            "this is unexpected")

        # 2. check if the schema version matches the router config
        for es_client in self.clients.values():
            if version in es_client.cfg.router.schema.versions:
                logging.debug(f"Document with $schema {schema_str} matches router's schema version, " + \
                              f"using ES client {es_client}")
                self.schema_map[schema_str] = es_client
                return es_client

        logging.warning("No specific ES client found for routing documents, using default one")
        # TODO: should we cache? unit test says no but we could?
        #self.schema_map[schema_str] = self.clients[self.default_version_if_no_schema]
        return self.clients[self.default_version_if_no_schema]

    def get_client_for_index(self, index_name):
        """
        Return ES client where client.index_name matches passed index_name
        (client responsible for managing given index)
        """
        def find():
            for client in self.clients.values():
                if client.index_name == index_name or client.index_name == self.aliases.get(index_name):
                    return client
        client = find()
        # no luck? maybe we updated aliases and they need to update?
        if not client:
            self.find_aliases()
            client = find()
            logging.info("Aliases refreshed, client for index '{}': {}".format(index_name,client))

        return client

    def parse_id(self, _id):
        return unpack_id(_id)

    @authfilter
    def fetch_by_id(self, _id, follow_link=False):
        """
        Return metadata file identified by its ID.

        Format: "<project_id>:<path>@<version|revision>"

        follow_link=True will follow link as defined in `_extra.link`
        and return the content of the link's target.
        """
        # can we find it if it's a revision (PUBLISHED-*) that was passed?
        ids = self.parse_id(_id)

        doc = None

        # And what if revision is "latest" (or "LATEST") ?
        latest = False
        if ids["version"].lower() == "latest":
            latest = self.find_latest_revision(ids["project_id"])
            if not latest:
                return None
            numrev = {"_extra.numerical_revision": latest}
            doc = self.fetch_by(**{"_extra.project_id":ids["project_id"],"path":ids["path"]},**numrev)
        else:
            # try with staight ID, no revision, no special "latest" case
            try:
                doc = self.fetch_by(**{"_extra.id":_id})
            except NotFoundError:
                # still no luck, can we find if consider passed version as an actual revision
                # (eg. proj_id:path@REVISION-1).
                try:
                    doc = self.fetch_by(**{
                        "_extra.project_id": ids["project_id"],
                        "path": ids["path"],
                        "_extra.revision": ids["version"]
                    })
                    #return doc
                except NotFoundError:
                    # maybe another es_client will find something
                    pass

        if doc is None:
            logging.info("File with _id {} can't be found".format(repr(_id)))
        elif doc._extra.link and follow_link:
            if doc._extra.link:
                assert "artifactdb" in doc._extra.link, f"Can't follow link {doc._extra.link}, not supported"
                new_id = doc._extra.link["artifactdb"]
                return self.fetch_by_id(new_id,follow_link)
        else:
            return doc

    @authfilter
    def fetch_by(self, **kwargs):
        """
        Same as search_by but expects only one result matching the query.
        Returns a DSL document, matching return type of fetch_by_id
        """
        res = self.search_by(**kwargs)
        found = len(res.get("hits",{}).get("hits",[]))
        if not found:
            raise NotFoundError(404,"Not Found","No document found")
        if found > 1:
            msg = "Expected only document matching query, got {}".format(found)
            logging.error(msg + ". Query: {}".format(kwargs))
            raise NotFoundError(409, "Conflict",msg)
        # convert to DSL doc. We need to ge the proper client for that
        hit = res["hits"]["hits"][0]
        es_client = self.get_client_for_index(hit["_index"])
        assert es_client, "No ES client found for index '{}'".format(hit["_index"])
        # from_es will make the document as if it was coming from fetch_by_id, ie. particularly
        # filtering out None/empty values
        doc = es_client.doc_class.from_es(hit)

        return doc

    @authfilter
    def search_one_by(self, **kwargs):
        """
        Same as search_by() but returns only one result.
        Can be used to probe data
        """
        # also get rid of scroll to avoid consume scroll resources for nothing
        # see Github issue #4
        return self.search_by(_={"size":1,"scroll":None},**kwargs)

    @authfilter
    def search_by(self, **kwargs):
        """
        Search documents matching given fields. OR boolean operation can be
        specified as: search_by(_="_extra.version=ABC|release=ABC",_extra.project_id="GPA8").
        (note the "_" value for the key, being ignored in the query generation
         process while "project_id" is passed as a key when no boolena op involved.

        Search arguments to change search behavior can be passed, with _={...}.
        Ex: return just one document
        search_by(_extra.project_id="GPA2",_extra.version="123",_={"size":1})
        """
        q_main = Search()
        search_args = dict(size=self.es_client.cfg.default_size,scroll=DEFAULT_SCROLL)
        for kw,kval in kwargs.items():
            if isinstance(kval,str) and "|" in kval:
                left,right = list(map(str.strip,kval.split("|")))
                leftname,leftval = left.split("=")
                rightname,rightval = right.split("=")
                q_or = Q("match",**{leftname:leftval}) | Q("match",**{rightname:rightval})
                q_main = q_main.query(q_or)
            elif isinstance(kval,str) and "!=" in kval:
                field,value = list(map(str.strip,kval.split("!=")))
                q_match = Q("match",**{field:value})
                q_main = q_main.filter("bool",must_not=[q_match])
            elif isinstance(kval,str) and "regexp:" in kval:
                regexp = str.replace(kval, "regexp:", "")
                q_main = q_main.query("regexp", **{kw:regexp})
            elif isinstance(kval,dict):
                # search behavior
                search_args.update(kval)
            else:
                q_main = q_main.query("match",**{kw:kval})

        return self.es_client.search(q_main,index=self.index_name,**search_args)

    @authfilter
    def search_by_project_id(self, project_id, version=None, fields=None):
        """
        Search all docs (metadata files) by project ID
        `fields` can be used to limit the number of returned fields.
        """
        sobj = Search().query("match",**{"_extra.project_id":project_id})
        version_q = None
        if version:
            if version.lower() == "latest":
                # special case
                latest = self.find_latest_revision(project_id)
                if not latest:
                    raise DataInconsistencyException("Latest revision couldn't be found, check if project exists")
                numrev = {"_extra.numerical_revision": latest}
                version_q = Q("match", **numrev)
            else:
                # search version and revision
                version_q = Q("match", **{"_extra.version":version}) | Q("match", **{"_extra.revision":version})
        if version_q:
            sobj = sobj.query(version_q)
        if fields:
            sobj = parse_fields(sobj,fields)
        return self.es_client.search(sobj,index=self.index_name,size=self.es_client.cfg.default_size,scroll=DEFAULT_SCROLL)

    @authfilter
    def search(self, q, fields=None, sort=None, size=None, latest=False, scroll="2m"):
        """
        'q' argument is evaled as a ES expression (eg. to what's passed to /_search?q=...)
        'fields' can be passed to select what fields from documents should be returned
        (dotfield notation is allowed).
        """
        query = parse_q(q,index_name=self.index_name)
        query = parse_fields(query,fields)
        query = self._sort(query,sort)
        query = self._size(query,size)
        if latest:
            response = self.es_client.search_latest(query,index=self.index_name,scroll=scroll)
        else:
            response = self.es_client.search(query,index=self.index_name,scroll=scroll)
        return response

    @authfilter
    def list_projects(self, q="*", order="asc", per="_extra.version", size=None, scroll="2m"):
        """
        List all projects and their versions. An optional query string can be used
        to filter out results.
        """
        query = parse_q(q,index_name=self.index_name)
        query = self._size(query,size)
        response = self.es_client.list_projects(query,order=order,per=per,index=self.index_name,scroll=scroll)

        return response

    def get_index_name_prefix(self):
        # the part {api_name}-{env} can't be known here, as we miss the {env}
        # from the config (root param, but we only have access to `es` section at this point)
        # + the API itself nevern know its own name {api_name}. So we'll analyze the active
        # indices (from `es`) to determine the final prefix {api_name}-{env}-{alias}-*
        common = os.path.commonprefix(self.active_indices)
        if not common:
            return None
        # all index name must have "{api_name}-{env}-" in common (by convention)
        # ex: api-test-v1 & api-test-v2 => api-test-v
        # ex: api-test-v3 & api-test-old => api-test-
        # ex api-test-v3-dynamic only => api-test-v3-dynamic
        parts = common.split("-")
        # we should have 3 parts: api_name, env, and trailing part after the last "-"
        # but the version (v3, v3-dynamic, ...) can be "-" in it so we just "eat" the first 2 parts
        # api_name and env, which by conventions can't have "-" in it
        assert len(parts) == 3, f"Inconsistent index names, can't determine common prefix: {self.active_indices}"
        parts.pop()
        api_name,env = parts[0],parts[1]
        prefix = f"{api_name}-{env}"

        return prefix

    def list_indices(self):
        """
        Return all indices per alias, including old indices not served anymore.
        Old indices are determined based on the index naming convention:
        {api_name}-{env}-{alias}-{timestamps}
        """
        prefix = self.get_index_name_prefix()
        if prefix:
            # TODO: what if we have hundreds of indices matching? unlikely though...
            indices = self.es_client.client.indices.get(index=f"{prefix}-*")
        else:
            indices = {}
        results = {
            "indices": {
                "active": {alias:None for alias in self.clients},
                "inactive": {alias:[] for alias in self.clients},
            },
            "total": len(indices)
        }
        for index_name,index_def in indices.items():
            result = {
                "name": index_name,
                "settings": index_def["settings"]["index"],
            }
            active = index_name in self.active_indices
            parts = index_name.replace(prefix,"").split("-")[1:]  # remove empty leading "-", from eg. "-v3-20220303"
            parts.pop()  # timestamp, we don't care
            # the rest is the alias (but it can contain "-" that's why we proceed that way by popping timestamp first)
            alias = "-".join(parts)
            if active:
                results["indices"]["active"][alias] = result
            else:
                results["indices"]["inactive"].setdefault(alias,[]).append(result)
        # sort inactive, newer to older
        for alias in results["indices"]["inactive"]:
            results["indices"]["inactive"][alias].sort(key=lambda e: int(e["settings"]["creation_date"]),reverse=True)

        return results

    def delete_index(self, index_name, force=False):
        """
        Delete an index by its name. The index name must the index prefix that all indices share in the API instance,
        unless force is True.
        """
        prefix = self.get_index_name_prefix()
        if not index_name.startswith(prefix) and not force:
            raise InvalidIndexNameError(f"Index named {index_name!r} doesn't follow index name prefix {prefix!r}")
        return self.es_client.client.indices.delete(index=index_name)

    def clean_inactive_indices(self, alias, keep=5):
        """
        Delete inactive/old indices for given Elastic `alias`, so only `keep` inactive indices are left.
        Oldest indices are deleted first. `keep` can be `None` meaning no old indices should be kepts.
        """
        all_indices = self.list_indices()
        inactives = all_indices["indices"]["inactive"][alias]
        count = len(inactives)
        assert keep >= 0
        deleted = []
        while count > keep:
            inactive = inactives.pop()  # sorted, so last ones are the oldest
            count -= 1
            index_name = inactive["name"]
            logging.info(f"Deleting old/inactive index {index_name!r}")
            self.delete_index(index_name,force=False)
            deleted.append(index_name)
        logging.info(f"Indices cleaned: {deleted}")

        return deleted

    def _size(self, query, size):
        if size is None:
            size = self.es_client.cfg.default_returned_results
        else:
            try:
                size = int(size)
            except ValueError as e:
                raise ValueError(f"Invalid value for size: {e}")
        if size > self.es_client.cfg.max_returned_results:
            logging.debug(f"'size' parameter ({size}) exceeding maximum allowed " + \
                          f"({self.es_client.cfg.max_returned_results}), adjusting")
            size = self.es_client.cfg.max_returned_results
        query = query.extra(size=size)

        return query

    def _sort(self, query, sort):
        if sort:
            if isinstance(sort,str):
                sort = [sort]
            # TODO: we would need to check field is sortable for each
            # mapping in underlying client...
            self.es_client.check_sortable(sort)
            query = query.sort(*sort)

        return query

    def _es_scroll(self, scroll_id, scroll=DEFAULT_SCROLL):
        return self.es_client.client.scroll(scroll_id=scroll_id, scroll=scroll)

    def _custom_scroll(self, scroll_id, scroll=DEFAULT_SCROLL):  # pylint: disable=unused-argument   # same _es_scroll() signature
        try:
            prefix, func_name, _id = scroll_id.split("-")
        except ValueError:
            raise CustomScrollError("Invalid custom scroll id '{}'".format(scroll_id))
        if prefix != "Y3VzdG9t":  # "custom" in base64
            raise CustomScrollError("Invalid custom scroll prefix '{}'".format(prefix))
        decoded = base64.b64decode(func_name).decode()
        try:
            method = getattr(self.es_client,decoded)
        except AttributeError:
            raise CustomScrollError("No such callable '{}' to handle custom scroll".format(decoded))


        return method(scroll_id)

    @authfilter
    def scroll(self, scroll_id, scroll=DEFAULT_SCROLL):
        # Y3VzdG9t == base64 encoded "custom"
        if scroll_id.startswith("Y3VzdG9t-"):
            results = self._custom_scroll(scroll_id,scroll=scroll)
        else:
            results = self._es_scroll(scroll_id,scroll=scroll)
        if len(results["hits"].get("hits",[])):
            return results
        else:
            # pop _scroll_id so client knows there's nothing to fetch anymore
            es_scroll_id = results.pop("_scroll_id",None)  # custom scrolls don't appear here when no data anymore
            if es_scroll_id:
                # clear the scroll to free a scroll slot
                self.es_client.client.clear_scroll(scroll_id=es_scroll_id)
            elif self.es_client.scroller:
                # clear custom scroll
                self.es_client.scroller.clear(scroll_id)

            return results

    def convert_revision_to_version(self, project_id, version_or_revision):
        """
        Convert 'version_or_revision' into version and return the result, or
        None if conversion couldn't be done.
        """
        if version_or_revision.lower() == "latest":
            version_or_revision = str(self.find_latest_revision(project_id))

        # first check with version
        results = self.search_one_by(**{
            "_extra.project_id": project_id,
            "_extra.version": version_or_revision,
        })
        if results and results["hits"]["hits"]:
            # found as a real version
            assert len(results["hits"]["hits"]) == 1
            assert results["hits"]["hits"][0]["_source"]["_extra"]["version"] == version_or_revision
            return version_or_revision
        # try again with revision now
        results = self.search_one_by(**{
            "_extra.project_id": project_id,
            "_extra.revision": version_or_revision
        })
        if results and results["hits"]["hits"]:
            # found as a real version
            assert len(results["hits"]["hits"]) == 1
            assert results["hits"]["hits"][0]["_source"]["_extra"]["revision"] == version_or_revision
            return results["hits"]["hits"][0]["_source"]["_extra"]["version"]
        # if we get there, nothing could be converted
        return None

    def find_latest_revision(self, project_id, query_field=None):
        """
        Returns latest revision (as an integer) found in all versions of project_id.
        Returns None if it doesn't exist.
        """
        project_id = escape_query_param(project_id)
        query_field = query_field or "_extra.project_id"  # "real" project_id by default
        q = f'''{query_field}:"{project_id}"'''
        # temporarily set a auth context to skip auth so latest revision
        # is always the actual latest one, and not what auth user can see
        subctx = skip_auth_context.set(True)
        try:
            result = self.aggregate(q,"max","_extra.numerical_revision","latest_revision")
        finally:
            skip_auth_context.reset(subctx)
        latest = result.get("aggregations",{}).get("latest_revision",{}).get("value")
        if not latest is None:
            latest = int(latest)  # python ES returns a float there, instead of a short (int)

        # this can't happen but "don't assume it, prove it"
        assert skip_auth_context.get() is False
        return latest

    def stats(self):
        per_models = {}
        for model,es in self.clients.items():
            count = es.client.count(index=es.index_name)["count"]
            per_models[model and model or "default"] = count

        return per_models

    def aggregate(self, q, agg_type, agg_field, agg_name, fields=None, size=0, scroll=None, agg_size=10, **kwargs):
        """
        Performs a aggregation of type "agg_type" (eg. "terms", "max"), querying data
        using "q" as selecting/filtering query, and "agg_field" as the term with which
        buckets are created. Each bucket then contains the number of documents (count)
        matching the add_field. "agg_name" is the name given to the aggregation
        (found in the results).

        "size" tells how many documents should be returned along with the aggregation
        results (none returned by default). If not 0, "fields" can be specified to select
        a subset of document's fields to return. Optional "scroll" can be specified (eg. 2m)
        if lots of results are expected to be returned (more than config.es.default_size).
        "agg_size" specifies the number of results in the aggregation. "agg_size"="all" will
        return all results (use with caution). Ignored if agg_type is "max".

        **kwargs is passed to query.aggs.bucket() method,
        Ex: order={"_count":"asc"}
        can be used to sort results of a "terms" aggregation
        """
        query = parse_q(q,index_name=self.index_name)
        if size:
            query = parse_fields(query,fields)
        # attempts to obtain a keyword field (dynamic:true will index string as "text"
        # + add a keyword sub-type. agg queries don't work on "text"). If no keyword
        # resolved, agg_field original value is kept, and we go with it from there.
        agg_field = self.resolve_field(agg_field,"keyword")
        buckets_args = {"name": agg_name, "agg_type": agg_type, "field": agg_field}
        if agg_type != "max":
            if agg_size == "all":
                # replace with number of docs returned by query
                agg_size = query.count()
            if not size is None:
                buckets_args["size"] = agg_size

        query.aggs.bucket(**buckets_args,**kwargs)
        response = self.es_client.search(query,index=self.index_name,scroll=scroll,size=size)

        return response

    def scan(self, q, fields=None):
        """
        Iterate over all documents mathing query 'q'
        Note documents can be fetched from any registered 'clients'
        (multi-index search is used behing the scene).
        """
        auth_q = authorize_query(q, index_name=self.index_name)
        if fields:
            auth_q = parse_fields(auth_q, fields)

        for doc in auth_q.scan():
            yield doc

    def delete_project(self, project_id, version=None):
        # using bulk, group by indices (ie. underlying ES clients)
        per_indices = {}
        # this goes through auth, first searching documents, so
        # only those which belong to auth user will be deleted
        results = self.search_by_project_id(project_id, version, fields=["_extra.id"])

        # first pass: scroll all docs
        while True:
            for hit in results["hits"]["hits"]:
                per_indices.setdefault(hit["_index"], []).append({"_id": hit["_id"]})
            scroll_id = results.get("_custom_scroll_id") or results.get("_scroll_id")
            if scroll_id:
                results = self.scroll(scroll_id)
            else:
                break

        # second pass: delete found docs (note: we can't deleting while scrolling because
        # deleting changes the number of pages potentially avail while scrolling, we could miss
        # documents (eventual consistency)

        # counts deleted docs, bulk() doesn't return that info, trying our best
        # here, a batch may fail half-way through, so not super reliable in case of errors
        deleted = 0
        for index_name, ids in per_indices.items():
            client = self.get_client_for_index(index_name)
            count = len(ids)
            client.bulk(ids, op="delete")
            deleted += count

        return deleted

    def find_links(self, project_id, version=None):
        """
        Return a list of {"id" => "artifactdb_id"} within a project/version,
        with "id" is a link pointing to an ArtifactDB ID "artifactdb_id".
        List is empty if no links found.
        """
        links = []
        q = f"""_extra.project_id:"{project_id}" AND _exists_:_extra.link"""
        if not version is None:
            q += f""" AND _extra.version:"{version}" """
        res = self.search(q,fields=["_extra.id","_extra.link"],sort="_extra.id")
        while True:
            for hit in res["hits"]["hits"]:
                doc = self.fetch_by_id(hit["_source"]["_extra"]["id"],follow_link=True)
                info = {
                    "id": hit["_source"]["_extra"]["id"],
                    "link": {
                        "artifactdb": doc and doc._id
                    }
                }
                links.append(info)

            if "_custom_scroll_id" in res:
                res = self.scroll(res["_custom_scroll_id"])
            else:
                break

        return links
