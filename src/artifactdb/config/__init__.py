import os
import logging
import logging.config

from aumbry import Attr

import artifactdb
from .utils import PrintableYamlConfig, ApiConfigBaseHandler, init_model
from .auth import AuthConfigBase
from .cors import CorsConfig
from .storages import set_storage_models, set_legacy_s3_config


class ArtifactDBConfigBase(PrintableYamlConfig):
    __handler__ = ApiConfigBaseHandler

    __mapping__ = {
        'gunicorn': Attr('gunicorn', dict),
        'auth': Attr('auth', AuthConfigBase),
        'cors': Attr('cors', CorsConfig),
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
    }

    # TODO: until __version__ is reworked as dict() of component's version
    artifactdb = artifactdb.utils.__version__
    prefixes = ["/", ]
    doc_url = None
    logo_url = None
    root_url = None
    # human-readable name & description about the instance
    name = None
    description = None

    # in order, as set_storage_models() will init actual config models instead of dict
    __handler__.post_hooks = [
        set_storage_models,
        set_legacy_s3_config,
    ]

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


