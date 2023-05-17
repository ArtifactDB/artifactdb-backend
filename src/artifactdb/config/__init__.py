import os
import copy
import logging
import logging.config

from typing import Optional
from aumbry import Attr

import artifactdb
from .utils import PrintableYamlConfig, ApiConfigBaseHandler, init_model
from .auth import AuthConfigBase
from .cors import CorsConfig
from .storages import set_storage_models, set_legacy_s3_config, StorageConfig, S3InventoryConfig
from .sequences import set_sequence_models, SequencesConfig
from .elasticsearch import ElasticMainConfig
from .locks import LockConfig
from .permissions import PermissionsConfig
from .schemas import SchemaConfig
from .gprns import GPRNConfig
from .events import HermesConfig


#########################
# Generic configuration #
#########################

class ConfigBase(PrintableYamlConfig):
    __handler__ = ApiConfigBaseHandler

    __mapping__ = {
        'gunicorn': Attr('gunicorn', dict),
        'auth': Attr('auth', AuthConfigBase),
        'cors': Attr('cors', CorsConfig),
        'hermes': Attr('hermes', HermesConfig),
        'version': Attr('version', str),
        'env': Attr('env', str),
        'build': Attr('build', str),
        'image': Attr('image', str),
        'artifactdb': Attr('artifactdb', str),
        'root_url': Attr('root_url', str),
        'doc_url': Attr('doc_url', str),
        'logo_url': Attr('logo_url', str),
        'name': Attr('name', str),
        'description': Attr('description', str),
        'prefixes': Attr('prefixes', list),
        'static_folder': Attr('static_folder', str),
    }

    # TODO: until __version__ is reworked as dict() of component's version
    artifactdb = artifactdb.utils.__version__
    prefixes = ["/", ]
    doc_url = None
    logo_url = None
    root_url = None
    hermes = HermesConfig()
    # human-readable name & description about the instance
    name = None
    description = None
    # folder containing static files, eg. for Swagger UI.
    static_folder = "./static"

    def __repr__(self):
        return "<{}: {}>".format(self.__class__.__name__, os.path.basename(self.config_file))

    def __init__(self):
        self.gunicorn = {}
        self.setup_loggers()
        self.config_file = None  # will be set by get_config() when loading file

    def setup_loggers(self):
        # providate standard (apache style) log statements for Uvicorn
        uvicorn_logger = {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "access": {
                    "()": "uvicorn.logging.AccessFormatter",
                    # 127.0.0.1 user-identifier frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
                    "fmt": '%(levelprefix)s %(asctime)s :: %(client_addr)s - "%(request_line)s" %(status_code)s',
                    "use_colors": True
                },
                "standard": {
                    "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
                },
            },
            "handlers": {
                "access": {
                    "formatter": "access",
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stdout",
                },
                "default": {
                    "level": "DEBUG",
                    "formatter": "standard",
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stdout",  # Default is stderr
                },
            },
            "loggers": {
                "uvicorn.access": {
                    "handlers": ["access"],
                    "level": "INFO",
                    "propagate": False
                },
            },
            "": {  # root logger
                "handlers": ["default"],
                "level": "DEBUG",
                "propagate": False
            },
        }

        try:
            logging.config.dictConfig(uvicorn_logger)
        finally:
            # not in a uvicorn environment (celery)
            logging.basicConfig(level=logging.DEBUG)
        # all verbose
        # then shut some mouths
        logging.getLogger("botocore").setLevel(logging.ERROR)
        logging.getLogger("boto3").setLevel(logging.ERROR)
        logging.getLogger("s3transfer").setLevel(logging.ERROR)
        logging.getLogger("parso").setLevel(logging.ERROR)
        logging.getLogger("urllib3").setLevel(logging.ERROR)
        logging.getLogger("elasticsearch").setLevel(logging.ERROR)
        logging.getLogger("blib2to3").setLevel(logging.ERROR)
        # when testing...
        logging.getLogger("pykwalify").setLevel(logging.ERROR)
        logging.getLogger("tavern").setLevel(logging.ERROR)
        logging.getLogger("amqp").setLevel(logging.ERROR)


############################
# Task store configuration #
############################

class TasksStoreConfig(PrintableYamlConfig):
    __mapping__ = {
        'backend': Attr('backend', dict),
        'cache_ttl': Attr('cache_ttl', Optional[int]),
        'key': Attr('key', list),
    }
    backend = {}
    cache_ttl = 43200 # 12 hours
    key = ""


########################
# Celery configuration #
########################

class CeleryConfig(PrintableYamlConfig):
    __mapping__ = {
        'broker_url': Attr('broker_url', str),
        'queues': Attr('queues', list),
        'repo': Attr('repo', list),
        'result_backend': Attr('result_backend', str),
        'tasks': Attr('tasks', dict),
        'tasks_store': Attr('tasks_store', TasksStoreConfig),
        'tasks_logs_count': Attr('tasks_logs_count', int)
    }

    broker_url = None
    queues = []
    repo = []
    result_backend = None
    tasks = {}
    tasks_store = {}
    tasks_logs_count = 10


#####################################
# ArtifactDB-specific configuration #
#####################################

class ArtifactDBConfigBaseHandler(ApiConfigBaseHandler):
    post_hooks = []


class ArtifactDBConfigBase(ConfigBase):
    __handler__ = ArtifactDBConfigBaseHandler
    # in order, as set_storage_models() will init actual config models instead of dict
    __handler__.post_hooks = [
        set_storage_models,
        set_sequence_models,
        set_legacy_s3_config,
    ]

    __mapping__ = {
        'es': Attr('es', ElasticMainConfig),  # {"<schema_version>": ElasticsearchConfig}
        'storage': Attr('storage', StorageConfig),
        'lock': Attr('lock', LockConfig),
        'permissions': Attr('permissions', PermissionsConfig),
        'schema': Attr('schema', SchemaConfig),
        # sequence config: legacy
        'sequence': Attr('sequence',list),
        # sequence config: new
        'sequences': Attr('sequences', SequencesConfig),
        's3_inventory':Attr('s3_inventory',S3InventoryConfig),
        'gprn': Attr('gprn', GPRNConfig),
        'celery': Attr('celery', CeleryConfig),
        'inspectors': Attr('inspectors',list),
    }

    sequence = []  # legacy
    sequences = SequencesConfig()
    inspectors = []
    s3_inventory = None
    permissions = PermissionsConfig()


