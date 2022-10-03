"""
Depencies module (as in FastAPI dependencies, what's injected in resource endpoints)
"""
import logging

from artifactdb.rest.auth import StandardAuthorizer, GuestAuthorizer
from artifactdb.rest.presign import RedisPresignURLManager


class DependencyManagerBase:

    class Singleton:

        def __init__(self, cfg=None, celery_app=None):
            self.cfg = cfg
            self.authorizer_class = StandardAuthorizer if self.cfg.auth.enabled else GuestAuthorizer
            self.celery_app = celery_app
            self.manager = self.celery_app.manager
            # authorizer for all "standard" users, no specific roles
            self.authorizers = {
                # default authorizer, when no roles/access_rules specified
                "": self.authorizer_class(self.cfg,self.manager.permissions_manager),
                (None,None): self.authorizer_class(self.cfg,self.manager.permissions_manager),
            }
            # presigned URLs for API itself, optional
            self.prepare_presign_manager()

        @property
        def s3_client(self):
            return self.manager.storage_manager.get_storage()

        @property
        def es_client(self):
            return self.manager.es

        def prepare_presign_manager(self):
            self.presign_manager = None
            if self.cfg.auth.presign:
                self.presign_manager = RedisPresignURLManager(self.cfg.auth.presign)

        def get_authorizer(self, roles=(), access_rules=("read_access",), op="or", read_eval_time="query"):
            keyauth = (frozenset(sorted(roles)),frozenset(sorted(access_rules)),read_eval_time)
            if keyauth not in self.authorizers:
                # for now, one auth'er per role
                self.authorizers[keyauth] = self.authorizer_class(self.cfg,
                        permissions_manager=self.manager.permissions_manager,
                        roles=roles,access_rules=access_rules,op=op,
                        read_eval_time=read_eval_time)
                logging.info("Registered authorizer: {}".format(self.authorizers[keyauth]))
            return self.authorizers[keyauth]

        def __str__(self):
            return repr(self)

    instance = None

    def __init__(self, cfg=None, celery_app=None):
        if not self.__class__.instance:
            assert cfg, "Configuration must be passed the first time to initialize the singleton"
            assert celery_app, "Celery application must be passed the first time to initialize the singleton"
            self.__class__.instance = self.__class__.Singleton(cfg,celery_app)

    def __getattr__(self, name):
        if name in ("get_authorizer",):
            return getattr(self.instance, "get_authorizer")
        if name.startswith("get_"):
            dep = name.replace("get_","")
            if name in ("get_es_client","get_s3_client","get_presign_manager"):
                # backward compat, direct attr from the singleton instance
                return lambda: getattr(self.instance,dep)
            return lambda: getattr(self.instance.manager,dep)
        else:
            return getattr(self.instance, name)

