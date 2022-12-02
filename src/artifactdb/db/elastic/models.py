# pylint: disable=unused-import  # keep generic types available to client imports
import io
import copy
import logging
from datetime import datetime

from elasticsearch_dsl import Document, InnerDoc, Text, Nested, Completion, Keyword, SearchAsYouType, \
                              Object, MetaField, analyzer, tokenizer, analysis, Field, Short, Date, Long

from artifactdb.identifiers.gprn import generate as generate_gprn, GPRNError
from artifactdb.utils.misc import get_class_from_classpath
from .convert import EsModelScript


# from https://www.elastic.co/guide/en/elasticsearch/reference/current/analysis-lang-analyzer.html#english-analyzer
english_possessive_stemmer = analysis.token_filter("english_possessive_stemmer",type="stemmer",language="english")
english_stop = analysis.token_filter("english_stop", type="stop",stopwords="_english_")
english_stemmer = analysis.token_filter('english_stemmer',type="stemmer",language="english")
english_analyzer = analyzer('english_lowercase',
    type = "custom",
    tokenizer="standard",
    filter=[english_possessive_stemmer,"lowercase",english_stop,english_stemmer],
)


# There's no Alias field in the lib, so this is a simple one...
class Alias(Field):

    def __init__(self, path, *args, **kwargs):
        super().__init__(*args,**kwargs)
        self.path = path

    def to_dict(self):
        return {
            "type": "alias",
            "path": self.path,
        }


class Permissions(InnerDoc):
    # TODO: same Permissions' pydantic
    owners = Keyword()
    viewers = Keyword()
    scope = Keyword()
    read_access = Keyword()
    write_access = Keyword()


class Transient(InnerDoc):
    expires_job_id = Keyword(required=True)
    expires_in = Date(required=True)


class Link(InnerDoc):
    artifactdb = Keyword()


class S3Location(InnerDoc):
    bucket = Keyword()
    url = Keyword()
    arn = Keyword()


class LocalLocation(InnerDoc):
    folder = Keyword


class RemoteLocation(InnerDoc):
    hostname = Keyword()
    path = Keyword()
    protocol = Keyword()


class Location(InnerDoc):
    type = Keyword()  # matching one of these below
    s3 = Object(S3Location)
    #local = Object(LocalLocation)
    #remote = Object(RemoteLocation)


class ExtraInfoBase(InnerDoc):
    # because this main field/key is named _extra, it's considered a meta-field
    # by ES, which means fields aren't search by default. To allow this, we need
    # to be explicit and copy the fields to "all" (see index settings)
    id = Keyword(required=True)
    project_id = Keyword(required=True,copy_to="all")
    version = Keyword(required=True,copy_to="all")  # TODO: handle short-hash ala github ? (first 6-chars)
    revision = Keyword(copy_to="all")
    numerical_revision = Short()
    metapath = Keyword(required=True,copy_to="all")
    permissions = Object(Permissions)
    # while v1 has a "type" field at root level, v2 hasn't. We normalize the field
    # here, always present in _extra, whatever the version. v1 document will duplicate
    # the root "type" in _extra
    type = Text(copy_to="all")
    # json/yaml metadata file timestamps
    meta_indexed = Date(required=True)  # indexing datetime
    meta_uploaded = Date()  # uploaded to S3
    # underlying file timestamp
    uploaded = Date()  # uploaded to S3
    file_size = Long()  # file size in bytes
    # transient uploads info
    transient = Object(Transient)
    # link to other artifacts
    link = Object(Link)
    # GPRN uniquely identifying the resource in GP
    gprn = Keyword(copy_to="all")
    # location (s3, local, ...)
    location = Object(Location)


# Tricky there... we want a $schema field, but in python, we can't have names starting
# with "$", so we have to enrich the mapping properties manually
# Also add subfield `keyword` to allow some aggregations
subkw = {'keyword': {'type': 'keyword', 'ignore_above': 256}}
ExtraInfoBase._doc_type.mapping.properties._params["properties"]["$schema"] = Text(copy_to="all",fields=subkw)
ExtraInfoBase._doc_type.mapping.properties._params["properties"]["type"] = Text(copy_to="all",fields=subkw)


class ArtifactDBDocumentBase(Document):

    all = Text()

    def init_from(self, **datadict):
        schema = False  # it could be None, so special value there
        if "$schema" in datadict:
            schema = datadict.pop("$schema")
        for k,v in datadict.items():
            setattr(self,k,v)
        self.meta.id = self._id
        self["_extra"]["id"] = self._id
        if schema is not False:
            self._extra["$schema"] = schema
        self["_extra"]["meta_indexed"] = datetime.now().astimezone()  # not exactly the index time but close...

    @property
    def _id(self):
        """
        Document ID (_id for ES), defined as:
        <projects_id>:<path>@<version>
        """
        # TODO: use artifactdb.identifiers.aid.generate
        return "{}:{}@{}".format(self["_extra"]["project_id"],self["path"],self["_extra"]["version"])

    @classmethod
    def create_aliases(cls):
        """
        For conveniency, some fields are searchable without prefix "_extra"
        """
        for field in ["project_id","version","revision"]:
            cls._doc_type.mapping.properties._params["properties"][field] = Alias("_extra.{}".format(field))

    def set_gprn(self, gprn_cfg):
        # verify config is enough
        try:
            # base
            dgprn = copy.deepcopy(gprn_cfg.to_dict())
            dgprn["type-id"] = "artifact"  # by default, for ArtifactDB APIs
            # doc specific
            dgprn["resource-id"] = self._id
            gprn = generate_gprn(dgprn)
        except GPRNError:
            gprn = None
        self["_extra"]["gprn"] = gprn



class ArtifactDBDocumentMinimal(ArtifactDBDocumentBase):
    """
    Defines a minimal model, usually used to bootstrap
    model generation, with artifactdb.tools.genmodels, which
    requires functional imports to start
    """
    class Meta:
        dynamic = MetaField('strict')
    class Index:
        name = None
        settings = {"query": {"default_field": "*,all"}}
    _extra = Object(ExtraInfoBase)
    # ArtifactDB identifier requires the `path` field referring to
    # the underlying data file
    path = Keyword()


class ArtifactDBDocumentDummy(ArtifactDBDocumentBase):

    class Meta:
        dynamic = MetaField('true')


###################
# MODEL PROVIDERS #
###################

class ModelProviderError(Exception): pass


class ModelProviderBase:

    def __call__(self, cfg, preview=False, force=False, provider_only=False):
        """
        Generate a model (or a preview). If the model is found in the cache,
        it is generated again, the cached version is used, unless `force` is True.
        provider_only=True only return the model provider instance, and doesn't generate
        the model.
        """
        raise NotImplementedError("implement me")

    def has(self, _, preview=False):
        """
        Return true if a model can be found or not, as an active model or a preview model.
        """
        raise NotImplementedError("implement me")

    def delete(self, _, preview=False):
        """
        Delete generated model.
        """
        raise NotImplementedError("implement me")


class StaticModelProvider(ModelProviderBase):

    def __call__(self, model, preview=False, force=False, provider_only=False):
        if provider_only:
            return self
        if preview:
            raise ModelProviderError("`preview=True` not allowed when using static models")
        return get_class_from_classpath(model)

    def has(self, model, preview=False):
        if preview:
            raise ModelProviderError("`preview=True` not allowed for static model providers")
        return self(model)

    def delete(self, model, preview=False):
        raise TypeError("Cannot delete a static model")


class SchemaBasedModelProvider(ModelProviderBase):

    def __init__(self, schema_manager):
        self.schema_manager = schema_manager

    def generate_model_name(self, schema_alias):
        model_name = "{}DynamicModel".format(schema_alias.capitalize().replace("-","_"))
        return model_name

    def generate_cache_key(self, schema_alias, preview=False):
        model_name = self.generate_model_name(schema_alias)
        cache_key = f"__model_{model_name}__"
        if preview:
            cache_key += "preview"

        return cache_key

    def generate_code(self, schema_client, model_name):
        buf = io.StringIO()
        # use the model generator script to fill a buffer with generated python code
        conv = EsModelScript(schema_client,buf,class_name=model_name,clear_cache=False)
        conv.generate()
        buf.seek(0)
        pysrc = buf.read()

        return pysrc

    def __call__(self, schema, preview=False, force=False, provider_only=False):
        if provider_only:
            return self
        schema_client = self.schema_manager[schema.alias]
        cache_key = self.generate_cache_key(schema.alias,preview)
        model_name = self.generate_model_name(schema.alias)
        pysrc = not force and schema_client.cache.get(cache_key)
        if pysrc:
            logging.info(f"Using cached model for schema with alias {schema.alias}")
        else:
            logging.info(f"Generating models based on schema with alias {schema.alias}")
            pysrc = self.generate_code(schema_client, model_name)
        # once we have the code, we can compile, eval and extract the class for the model
        bcode = compile(pysrc,"","exec")
        _ns = {}
        eval(bcode,_ns,_ns)  # pylint: disable=eval-used  # this is how we compile models for now
        klass = _ns[model_name]
        # looks like we could generate that class, let's cache it
        # ttl is None, to prevent the API to regenerate the models each
        # there's restart, this could take long, leads to some timeout errors
        # from github or gitlab. We want to be conservative to store
        # models that worked before, and let the cache handling to outside
        schema_client.cache.set(cache_key,pysrc,ttl=None)  # cache the source code, in case we need to display it later

        return klass

    def has(self, schema, preview=False):
        schema_client = self.schema_manager[schema.alias]
        cache_key = self.generate_cache_key(schema.alias,preview)
        return schema_client.cache.get(cache_key)

    def delete(self, schema_alias, preview=False):
        schema_client = self.schema_manager[schema_alias]
        cache_key = self.generate_cache_key(schema_alias,preview)
        return schema_client.cache.delete(cache_key)


class DynamicModelProviderBase(ModelProviderBase):

    def __init__(self, schema_manager):
        self.schema_manager = schema_manager
        self.providers_map = {
            "schema": SchemaBasedModelProvider(self.schema_manager),
        }

    def __getitem__(self, provider_type):
        return self.providers_map[provider_type]

    def _get_provider(self, dynamic_section):
        if dynamic_section.schema.to_dict():
            return (self.providers_map["schema"],dynamic_section.schema)
        else:
            raise NotImplementedError(f"Unsupported dynamic section: {dynamic_section}")


    def __call__(self, dynamic_section, preview=False, force=False, provider_only=False):
        """
        Dynamically generate a model class from the config section under
        `dynamic`, ex: {"schema": {"alias" : "v3"}}
        """
        provider,cfg_section = self._get_provider(dynamic_section)
        return provider(cfg_section,preview=preview,force=force,provider_only=provider_only)

    def has(self, dynamic_section, preview=False):
        provider,cfg_section = self._get_provider(dynamic_section)
        return provider.has(cfg_section,preview=preview)

    def delete(self, model, preview=False):
        raise TypeError("Cannot delete a dynamic model from the provider (use schema based model provider)")


class ModelProviderManager:

    def __init__(self, es_manager):
        self.es = es_manager
        self.schema_manager = self.es.schema_manager
        self.providers_map = {
            "static": StaticModelProvider(),
            "dynamic": DynamicModelProviderBase(self.schema_manager),
        }

    def __getitem__(self, provider_type):
        return self.providers_map[provider_type]

    def _get_provider(self, cfg):
        if cfg.dynamic.to_dict():
            return (self.providers_map["dynamic"],cfg.dynamic)
        else:
            return (self.providers_map["static"],cfg.model)

    def __call__(self, cfg, preview=False, force=False, provider_only=False):
        """
        Return a class corresponding to the model the client is in charge of.
        The model can come from a static declaration (`self.cfg.model`) pointing
        to an existing file, or can be dynamically generated (`self.cfg.dynamic`).
        """
        provider,cfg_section = self._get_provider(cfg)
        return provider(cfg_section,preview=preview,force=force,provider_only=provider_only)

    def has(self, es_alias, preview=False):
        cfg = self.es.clients[es_alias].cfg
        provider,cfg_section = self._get_provider(cfg)
        return provider.has(cfg_section,preview=preview)

