# pylint: disable=attribute-defined-outside-init
# init() plays the role of __init__() in backend component
import logging

from artifactdb.backend.components import WrappedBackendComponent
from artifactdb.db.elastic.manager import ElasticManager as ElasticManagerWrapped, NotFoundError
from artifactdb.db.elastic.client import AliasNotFound
from artifactdb.db.elastic.alias import update_es_aliases, CREATE_ALIAS, REMOVE_ALIAS, OUT_OF_SYNC, \
                                   MISSING, SYNCED


class ElasticManager(WrappedBackendComponent):

    NAME = "es"
    FEATURES = ["indexing",]
    DEPENDS_ON = ["revision_manager",]

    def init(self):
        self.front_es = None
        logging.info("Using Elasticsearch config: {}".format(self.main_cfg.es.backend))
        self.prepare_es_aliases()

    def wrapped(self):
        return ElasticManagerWrapped(
            self.main_cfg.es,"backend",self.main_cfg.es.scroll,
            self.main_cfg.es.switch,self.main_cfg.gprn,
            self.main_cfg.schema
        )

    def prepare_es_aliases(self):
        # check frontend clients as well, whether aliases are needed
        # First, make sure aliases exists. Frontend ES manager can know that on its own.
        def front_es():
            self.front_es = ElasticManagerWrapped(self.main_cfg.es,"frontend",self.main_cfg.es.scroll,
                                           self.main_cfg.es.switch,self.main_cfg.gprn,self.main_cfg.schema)
        try:
            front_es()
        except AliasNotFound as e:
            logging.warning(f"Missing Elasticsearch alias: {e}")
            if self.main_cfg.es.auto_create_aliases:
                self.update_es_aliases(ask=False,ops=["create"])
            front_es()
        # Second, we need to check if the aliases are in-sync, pointing to the right index defined in section backend
        report = self.es_aliases(status=OUT_OF_SYNC)
        if report:
            logging.warning(f"Out-of-sync Elasticsearch alias: {report}")
            if self.main_cfg.es.auto_sync_aliases:
                self.update_es_aliases(ask=False,ops=["move"])

    def es_aliases(self, status=None):
        """
        Return aliases (per clients) as currently active in Elasticsearch.
        `status` can be used to specifically request client with given status.
        """
        per_clients = {}
        for name,cfg in self.main_cfg.es.frontend.clients.items():
            if cfg.get("alias"):
                idx = self.main_cfg.es.backend.clients[name]["index"]
                per_clients[name] = {
                    "alias": None,
                    "index": idx,  # what's defined in config
                    "target": None,  # what's actually pointing to
                    "status": None,
                }
                alias = cfg["alias"]
                per_clients[name]["alias"] = alias
                try:
                    info = self.es_client.client.indices.get_alias(name=alias)
                except NotFoundError:
                    per_clients[name]["status"] = MISSING
                    continue
                targets = list(info)
                assert len(targets) == 1
                target = targets.pop()
                per_clients[name]["target"] = target
                if idx != target:
                    logging.warning(f"Alias '{alias}' points to '{target}' instead of '{idx}'")
                    per_clients[name]["status"] = OUT_OF_SYNC
                else:
                    per_clients[name]["status"] = SYNCED

        if status:
            # should we keep according to requested status?
            for name in list(per_clients):
                if status != per_clients[name]["status"]:
                    per_clients.pop(name)

        return per_clients

    def es_aliases_synced(self):
        """
        Return whether frontend aliases are in sync with backend indices.
        - True: aliases are in sync
        - False: aliases not in sync
        - None: there's no aliases
        If missing alias, raises AliasNotFound()
        """
        report = self.es_aliases()
        for info in report.values():
            if info["status"] != SYNCED:
                return False
        # empty report means there's no aliases found
        return True if report else None

    def update_es_aliases(self, clients=None, ops=("create","move"),ask=True):
        if clients:
            if isinstance(clients,str):  # it's a single client alias
                clients = {clients:self.clients[clients]}
            else:
                assert isinstance(clients,dict), "Expected client alias or dict of clients"
        else:
            clients = self.clients

        allowed_ops = set()
        if "create" in ops:
            allowed_ops.add(CREATE_ALIAS)
        if "move" in ops:
            # move means remove+create (it's done as an atomic operation)
            allowed_ops.add(CREATE_ALIAS)
            allowed_ops.add(REMOVE_ALIAS)

        return update_es_aliases(clients,self.cfg,ops=list(allowed_ops),ask=ask)

