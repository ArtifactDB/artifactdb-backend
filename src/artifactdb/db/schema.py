import os
import json
import pickle
import logging
import glob
import hashlib
from urllib.parse import urlparse, quote

import requests
import jsonref
from nested_lookup import nested_alter
import jsonschema

from artifactdb.config.schemas import SchemaClientConfig
from artifactdb.utils.misc import get_class_from_classpath
from artifactdb.backend.caches import get_cache


class SchemaClientError(Exception): pass
class SchemaNotFoundError(Exception): pass
class NoSchemaError(Exception): pass
class ValidationError(Exception): pass


class SchemaClientManager:

    instance = None

    class Singleton:

        def __init__(self, schema_cfg):
            self.schema_cfg = schema_cfg
            self.cache_ttl = self.schema_cfg.cache_ttl
            self.cache_client = get_cache(schema_cfg)

            self.clients = []
            self.cache = {}  # schema => client
            self.prepare_schema_clients()

        def prepare_schema_clients(self):
            for client_cfg in self.schema_cfg.clients:
                cfg = SchemaClientConfig()
                # if cache define in client confi
                if "cache_ttl" not in client_cfg:
                    client_cfg["cache_ttl"] = self.cache_ttl
                cfg.init_from(client_cfg)

                # add cache client to SchemaClientConfig
                setattr(cfg, 'cache', self.cache_client)

                client_class = get_class_from_classpath(cfg.client)
                client = client_class(cfg)
                if client.alias in [cl.alias for cl in self.clients]:
                    raise SchemaClientError(f"Schema alias {client.alias} already registered")
                self.clients.append(client)

        def get_client_for_document(self, document_type, document_version):
            cache_key = (document_type, document_version)
            client = self.cache.get(cache_key)
            if not client:
                # go through the process of fetching the schema, to fill
                # to fill the schema client cache
                schema = self.get_schema(document_type,document_version)
                if not schema:
                    return None
                client = self.cache.get(cache_key)
                assert client

            return client

        def get_types(self):
            types = []
            for client in self.clients:
                client_types = client.get_types()
                if client_types:
                    types.extend(client_types)

            return types

        def get_versions(self, doc_type):
            versions = []
            for client in self.clients:
                client_versions = client.get_versions(doc_type)
                if client_versions:
                    versions.extend(client_versions)

            return versions

        def get_schema(self, document_type, document_version):
            # did we already found the client for that doc/version?
            # and is its data still valid (ie. not expired)
            cache_key = (document_type, document_version)
            client = self.cache.get(cache_key)
            if client and not client.expired(document_type, document_version):
                return client.get_schema(document_type, document_version)
            # not in cache, explore
            schema = None
            valid_client = None
            for client in self.clients:
                schema_client_data = client.get_schema(document_type, document_version)
                if schema_client_data:
                    schema = schema_client_data
                    valid_client = client
            # cache the association
            if valid_client:
                self.cache[cache_key] = valid_client

            return schema

        def delete_client_cache(self, client=None):
            """
            Clear cache (schemas, versions, types) for all clients (or specific given `client`)
            """
            available_cache_keys = self.cache_client.keys()
            filtered_keys = []
            if client:  # add client into list so delete cache process should same if client given or not.
                filtered_keys = list(
                    filter(lambda a: client in a.decode('utf-8') if isinstance(a, bytes) else a, available_cache_keys))
            else:
                schema_alias_list = [client['alias'] for client in self.schema_cfg.clients]
                for schema_alias in schema_alias_list:
                    # pylint: disable=cell-var-from-loop  # matching schema_alias
                    filtered_keys += list(
                        filter(lambda a: schema_alias in a.decode('utf-8') if isinstance(a, bytes) else a,
                               available_cache_keys))
            logging.info(f"Found Cache {filtered_keys}")
            self.cache_client.clear(filtered_keys)

    def __init__(self, schema_config):
        if not self.__class__.instance:
            self.__class__.instance = self.__class__.Singleton(schema_config)

    def validate(self, doc):
        if not isinstance(doc,dict) or not doc:
            raise TypeError("Document is not a dict or is empty")
        if doc.get("$schema"):
            schema_name, schema_version = doc["$schema"].split("/")
            schema = self.get_schema(schema_name, schema_version)
            if schema:
                try:
                    jsonschema.validate(doc, schema)
                except jsonschema.exceptions.ValidationError as e:
                    raise ValidationError(f"Document couldn't be validated (schema {schema_name}/{schema_version}) " + \
                                          f"because {e}. Document was {doc}")
            else:
                raise SchemaNotFoundError(f"Could not find schema '{schema_name}/{schema_version}'")
        else:
            raise NoSchemaError("Document has no $schema field")

    def __getitem__(self, schema_alias):
        clients = [cl for cl in self.clients if cl.alias == schema_alias]
        if not clients:
            raise KeyError(schema_alias)
        assert len(clients) == 1
        return clients[0]

    def __getattr__(self, name):
        return getattr(self.instance, name)

    def __repr__(self):
        return f"<{self.__class__.__name__} {[cl.alias for cl in self.clients]}>"


class SchemaClient:
    def __init__(self, schema_cfg):
        self.schema_cfg = schema_cfg
        self.base_uri = self.schema_cfg.base_uri
        self.cache_ttl = self.schema_cfg.cache_ttl
        self.folder = self.schema_cfg.folder
        self.types = self.schema_cfg.types if hasattr(self.schema_cfg, 'types') else []
        self.alias = self.schema_cfg.alias if hasattr(self.schema_cfg, 'alias') else "Schema"
        # use a cache to get info from github/gitlab, speed up requests
        self.cache = self.schema_cfg.cache

    def clear(self):
        """
        Clear cache for force-reload schema from scratch
        """
        self.cache.clear()

    def expired(self, doc_type, version):
        cache_key = f"{self.alias}/{doc_type}/{version}"
        return self.cache.expired(cache_key)

    def get_types_url(self):
        raise NotImplementedError("Implement me in sub-class")

    def get_versions_url(self, doc_type):
        raise NotImplementedError("Implement me in sub-class")

    def checksum(self):
        """
        Compute a checksum on current schemas held by the client.
        This information is used to determine if there was a change
        in the schemas, possibly requiring a model update.
        """
        raise NotImplementedError("Implement me in sub-class")

    def _types_as_list(self, all_types):
        return [_["name"] for _ in all_types]

    def get_types(self, as_list=False):
        cache_key = self.alias
        url = self.get_types_url()
        if self.cache.expired(cache_key):
            resp = requests.get(url)
            types = []
            if resp.status_code != 200:
                logging.error(resp.text)
            else:
                types = resp.json()
            types = [elem for elem in types \
                     if not elem["name"].startswith("_") \
                     and elem["type"] in ("dir", "tree")]
            # sub-selection of types or all of them?
            if self.types:
                include_types = [_ for _ in self.types if not _.startswith("!")]
                exclude_types = [_ for _ in self.types if _.startswith("!")]
                if include_types:
                    types = [elem for elem in types \
                             if elem["name"] in include_types]
                if exclude_types:
                    types = [elem for elem in types \
                             if not "!{}".format(elem["name"]) in exclude_types]
            self.cache.set(cache_key, json.dumps(types), self.cache_ttl)

        all_types = json.loads(self.cache.get(cache_key))
        if as_list:
            return self._types_as_list(all_types)
        else:
            return all_types

    def get_versions(self, doc_type):
        if not doc_type in self.get_types(as_list=True):
            return []  # not handled by client (see include/exclude type lists)
        cache_key = f"{self.alias}/{doc_type}"
        url = self.get_versions_url(doc_type)
        if self.cache.expired(cache_key):
            resp = requests.get(url)
            versions = []
            if resp.status_code != 200:
                logging.error(f"Error fetching versions for document type {doc_type}: {resp.text}")
            else:
                # we're expecting a list (from a directory listing), otherwise we hit a file, not expected
                versions = resp.json()
                if isinstance(versions, list):
                    versions = [elem for elem in versions \
                                if not elem["name"].startswith("_") \
                                and elem["type"] in ("file", "blob")]
                else:
                    logging.warning(f"Ignoring {doc_type}, not directory")
                    versions = []  # reset

            self.cache.set(cache_key, json.dumps(versions), self.cache_ttl)

        return json.loads(self.cache.get(cache_key))

    def _perform_request(self, url):
        res = requests.get(url)
        if res.status_code == 404:
            return None
        try:
            result = res.json()
            return result
        except json.JSONDecodeError as e:
            logging.error(f"Can't parse schema as json: {e}: {res.text}")
            raise


    def get_schema(self, doc_type, version):
        raise NotImplementedError("Implement me in sub-class")

    def __repr__(self):
        return f"<{self.__class__.__name__} {self.alias} ({self.base_uri})>"


class SchemaClientGithub(SchemaClient):

    def __init__(self, schema_cfg):
        super().__init__(schema_cfg)
        self.actions = requests.get(self.base_uri).json()
        # preformat content URL, python-like
        self.content_url = self.actions["contents_url"].replace("{+path}", "%(path)s")
        # for v2 schema -> add branch name in the reference
        sha = "master"
        if 'ref' in self.base_uri:
            parsed = urlparse(self.base_uri)
            self.content_url += "?" + parsed.query
            sha = parsed.query.split("=")[1]
        self.commits_url = self.actions["commits_url"].replace("{/sha}",f"/{sha}")

    def get_types_url(self):
        url = self.content_url % {"path": self.folder}
        return url

    def get_versions_url(self, doc_type):
        url = self.content_url % {"path": os.path.join(self.folder, doc_type)}
        return url

    def checksum(self):
        """
        Return the latest commit sha as the checksum, any changes on the repo
        will be reflected by a change.
        """
        resp = requests.get(self.commits_url)
        if resp.status_code != 200:
            raise SchemaClientError(resp.text)
        return resp.json()["sha"]

    def get_schema(self, doc_type, version):
        if not doc_type in self.get_types(as_list=True):
            return None
        cache_key = f"{self.alias}/{doc_type}/{version}"
        if self.cache.expired(cache_key):
            result = self._perform_request(self.content_url % {"path": os.path.join(self.folder, doc_type, version)})
            if result is None:
                schema = None
            else:
                url = result["download_url"]
                # let jsonref resolve all $ref, to get a final merged/resolved schema
                try:
                    schema = jsonref.load_uri(url)
                except jsonref.JsonRefError as e:
                    logging.warning(f"Unable to resolve schema for '{os.path.join(doc_type, version)}': {e}")
                    schema = None
            # dict isn't jsonifyable ("dict is not JSON serializable", which it is, so it must be a kind of dict but not
            # really). Going through pickle restores the real dict type and makes it JSON serializable...
            self.cache.set(cache_key, pickle.dumps(schema), self.cache_ttl)
        return pickle.loads(self.cache.get(cache_key))


class SchemaClientGitlab(SchemaClient):

    def __init__(self, schema_cfg):
        super().__init__(schema_cfg)
        parsed = urlparse(self.base_uri)

        # content URL
        content_path = os.path.join(parsed.path, "files/{}/raw")
        self.content_url = parsed._replace(path=content_path).geturl()
        # Url to access tree
        tree_path = os.path.join(parsed.path, "tree")
        self.tree_url = parsed._replace(path=tree_path).geturl()
        self.per_page = self.schema_cfg.extra.get('per_page', 20)  # for gitlab api
        # commit URLs
        commits_path = os.path.join(parsed.path, "commits")
        self.commits_url = parsed._replace(path=commits_path).geturl()
        # folder & file path are passed as arg in query string, needs to encode / into %2F
        # in case the path pointing to folder holding all schemas has multiple levels
        self.folder = self.folder.replace('/', '%2F')

    def get_types_url(self):
        url = self.tree_url + f"&path={self.folder}" + f"&per_page={self.per_page}"
        return url

    def get_versions_url(self, doc_type):
        path = f"{self.folder}/{doc_type}" if self.folder else f"{doc_type}"
        url = self.tree_url + f"&path={path}" + f"&per_page={self.per_page}"
        return url

    def checksum(self):
        """
        Return the latest commit sha as the checksum, any changes on the repo
        will be reflected by a change.
        """
        resp = requests.get(self.commits_url)
        if resp.status_code != 200:
            raise SchemaClientError(resp.text)
        return resp.json()[0]["id"]

    def get_schema(self, doc_type, version):

        def callback(value):
            if not value.startswith("#/definitions"):
                parsed = urlparse(value)
                if parsed.scheme == "file":
                    # resolution from local filesystem, no need to twist the value
                    return value
                # quote function replace "/" with "%2F"
                callback_path = quote(parsed.path, safe='').replace("..%2F","")
                if self.folder:
                    callback_path = f"{self.folder}%2F" + callback_path
                url = self.content_url.format(callback_path)
                if parsed.fragment:
                    url += "#" + parsed.fragment
                return url
            else:
                return value

        if not doc_type in self.get_types(as_list=True):
            return None
        cache_key = f"{self.alias}/{doc_type}/{version}"
        if self.cache.expired(cache_key):
            path_list = [doc_type,version]
            if self.folder:
                path_list.insert(0, self.folder)
            path = "%2F".join(path_list)
            result = self._perform_request(self.content_url.format(path))
            if result is None:
                schema = None
            else:
                # let jsonref resolve all $ref, to get a final merged/resolved schema
                try:
                    altered_document = nested_alter(result, "$ref", callback)
                    schema = jsonref.loads(str(json.dumps(altered_document)))
                except jsonref.JsonRefError as e:
                    logging.warning(f"Unable to resolve schema for '{os.path.join(doc_type, version)}': {e}")
                    schema = None
            self.cache.set(cache_key, pickle.dumps(schema), self.cache_ttl)
        return pickle.loads(self.cache.get(cache_key))


class SchemaClientLocal(SchemaClient):
    """
    Client operating on the filesystem as the source of JSON
    schema. Mostly for dev/test purpose. There's no caching
    happening, information (types, versions, schemas) are always
    read from the filesystem.
    """

    def __init__(self, schema_cfg):
        super().__init__(schema_cfg)
        self.init()

    def get_types_url(self):
        raise TypeError("SchemaClientLocal can't have a URL for types")

    def get_versions_url(self, doc_type):
        raise TypeError("SchemaClientLocal can't have a URL for versions")

    def init(self):
        self.schema_files = list(glob.glob(f"{self.base_uri}/**/*.json"))
        self.schema_store = {}
        for schema_file in self.schema_files:
            schema = json.load(open(schema_file))
            try:
                self.schema_store[schema["$id"]] = schema
            except KeyError as e:
                logging.error(f"Unable to register schema '{schema_file}' in store: {e}")
        self.loader = jsonref.JsonLoader(store=self.schema_store)

    def clear(self):
        super().clear()
        self.init()

    def _clean(self, path):
        return path.replace(self.base_uri,"").lstrip("/")

    def _types_as_list(self, all_types):
        return [list(_.values())[0] for _ in all_types]

    def checksum(self):
        """
        Schemas are stored locally on the file system, all schemas
        are read and md5sum is computed on the whole.
        """
        schemas = []
        for typ in self.get_types(as_list=True):
            for ver in self.get_versions(typ):
                schemas.append(self.get_schema(typ,ver["name"]))
        strschemas = "".join(sorted([json.dumps(sch) for sch in schemas]))
        md5sum = hashlib.md5(strschemas.encode())

        return md5sum.hexdigest()

    def get_types(self, as_list=False):
        content = glob.glob(os.path.join(self.base_uri,"**"))
        stypes = set()
        for _type in content:
            if not os.path.isdir(_type):
                continue
            _type = self._clean(_type)
            if _type.startswith("_"):
                continue
            stypes.add(_type)
        all_types = [{"name": _type} for _type in stypes]
        if as_list:
            return self._types_as_list(all_types)
        else:
            return all_types

    def get_versions(self, doc_type):
        if not doc_type in self.get_types(as_list=True):
            return []
        content = glob.glob(os.path.join(self.base_uri,doc_type,"**","*.json"),recursive=True)
        versions = [{"name": self._clean(ver).lstrip(doc_type).lstrip("/")} for ver in content]

        return versions

    def get_schema(self, doc_type, version):
        if not doc_type in self.get_types(as_list=True):
            return None
        schema_file = os.path.join(self.base_uri,doc_type,version)
        try:
            schema = jsonref.load(open(schema_file),loader=self.loader)
        except (jsonref.JsonRefError,FileNotFoundError) as e:
            logging.warning(f"Unable to resolve schema for '{os.path.join(doc_type, version)}': {e}")
            schema = None

        return pickle.loads(pickle.dumps(schema))
