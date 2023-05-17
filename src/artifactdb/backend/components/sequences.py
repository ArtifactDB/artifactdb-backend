import os
import urllib
import logging
from pprint import pprint
from abc import abstractmethod

from sqlalchemy import create_engine, text, inspect
from sqlalchemy.exc import InternalError

from artifactdb.backend.components import BackendComponent
from artifactdb.config.sequences import SequenceConfig
from artifactdb.utils.context import sequence_context_name
import artifactdb.resources.sql


class SequenceError(Exception): pass
class SequenceContextError(SequenceError): pass
class SequencePoolError(SequenceError): pass
class SequenceEmptyError(SequenceError): pass
class SequenceVersionError(SequenceError): pass


class BaseSequenceClient:

    def __init__(self, client_conf, storage_provider=None, sql_folder=None, use_pools=True):
        self.cfg = client_conf
        # inject user/pass uri (with this infamous urllib "lib"...)
        noauth_uri = urllib.parse.urlsplit(self.cfg.uri)
        db_user = self.cfg.db_user
        db_password = self.cfg.db_password
        auth_netloc = f"{db_user}:{db_password}@{noauth_uri.hostname}"
        auth_uri = noauth_uri._replace(netloc=auth_netloc)  # urllib, thank you.
        self.uri = urllib.parse.urlunsplit(auth_uri)
        self.schema_name = self.cfg.schema_name.lower()  # psql seems to lowercase them
        self.max_sequence_id = self.cfg.max_sequence_id
        # where to init sequence from (templated SQL files)
        self.sql_folder = sql_folder or os.path.dirname(artifactdb.resources.sql.__file__)
        self.storage_provider = storage_provider
        self.use_pools = use_pools
        self.init()

    @property
    def s3(self):  # pylint: disable=invalid-name
        return self.storage_provider() if self.storage_provider else None

    @property
    def engine(self):
        # TODO: without re-creating an engine each we need one, we get errors like
        # "error with status PGRES_TUPLES_OK and no message from the libpq", apparently/possibly
        # due to engine being used across processed. Not the case here though? I don't know what's going on,
        # but the solution might be to use a thread safe pool of connections, or a pool that knows when
        # to re-create connections. For now, it's not optimal but it works...
        return create_engine(self.uri,echo=self.cfg.debug)


    @abstractmethod
    def init(self, purge=False):
        pass



class SequenceClient(BaseSequenceClient):

    def init(self, purge=False):
        with self.engine.connect().execution_options(autocommit=True) as conn:
            if purge:
                logging.warning(f"Init purge={purge}, dropping schema {self.schema_name}")
                conn.execute(text(f"DROP SCHEMA IF EXISTS {self.schema_name} CASCADE"))
            inspector = inspect(conn)
            if not self.schema_name in inspector.get_schema_names():
                logging.info(f"Creating schema '{self.schema_name}' holding sequence objects")
                sql_files = sorted([f for f in os.listdir(self.sql_folder) if f.endswith("sql.tpl")])
                for sql_file in sql_files:
                    full_path = os.path.join(self.sql_folder,sql_file)
                    logging.info(f"Executing {sql_file}")
                    tpl_sql = open(full_path).read()
                    sql = tpl_sql.format(schema_name=self.schema_name)
                    conn.execute(text(sql))
                if self.use_pools:
                    self.init_pools()
            else:
                logging.info(f"Schema '{self.schema_name}' exists, all good!")

    def init_pools(self):
        if self.cfg.auto_create_pool:
            # create default provisioned pool so the sequence is ready to be used
            # without any restrictions
            limits = (1,self.cfg.max_sequence_id)
            logging.info(f"Creating default provisioned pool {limits}")
            self.create_provisioned_pool(*limits)
        else:
            raise SequencePoolError("No provisioned pool, use sync() to synchronize the sequence from storage")

    def _fetch_from_s3(self):
        assert self.s3, "Can't synchronize sequence, no 's3' client available"
        from_s3 = {}
        logging.debug(f"Listing all projects in s3 starting with {self.cfg.project_prefix}")
        pids = list(self.s3.list_projects(prefix=self.cfg.project_prefix))
        total = len(pids)
        for i,pid in enumerate(pids):
            try:
                # make sure we can parse the project_id (strictly match our prefix)
                self._strip_prefix(pid)
            except SequenceError as exc:
                logging.warning(f"Discarding {pid}: {exc}")
                continue
            svers = sorted([int(_) for _ in self.s3.list_versions(pid)])
            from_s3[pid] = svers[-1]
            logging.debug(f"Found data for project {pid}: {from_s3[pid]} ({i+1}/{total})")

        return from_s3

    def _fetch_from_db(self, conn):
        from_db = {}
        logging.debug("Listing artifacts/versions currently in sequence")
        total = conn.execute(text(f"SELECT count(*) from {self.schema_name}.artifact_versions")).all()[0][0]
        cnt = 0
        for row in conn.execute(text(f"SELECT artifact_seq,curr_version_num from {self.schema_name}.artifact_versions")):
            pid = self._format_project_id(row[0])
            ver = row[1]
            logging.debug(f"Found sequence for project {pid}: {ver} ({cnt+1}/{total})")
            from_db[pid] = ver
            cnt += 1

        return from_db

    def reconcile(self, from_s3, from_db):
        """
        Identify missing artifact/version that are present in
        `from_s3` but not in `from_db`. Warnings for the opposite
        (info in sequence doesn't relate to existing data on s3).
        Finally, identify the max value for artifact ID (ie.
        lower limit for the provisioned pool)
        """
        todo = {"missing": {}, "max": None}
        max_pid = 0
        # what we need to add to the sequence
        for pid in from_s3:
            if not pid in from_db:
                logging.debug(f"Missing project {pid} (version: {from_s3[pid]}) in sequence")
                todo["missing"][pid] = from_s3[pid]
            num_pid = self._strip_prefix(pid)
            if num_pid > max_pid:
                max_pid = num_pid
        # what we have in the sequence that is not on s3
        # (can't do much about it, just reporting it)
        # note: we keep track of max ID in the sequence, *even* if no
        # data on S3, because the sequence ID may been served (provisioned)
        # but the data not uploaded yet.
        for pid in from_db:
            if not pid in from_s3:
                logging.debug(f"Sequence holds information about project {pid} but no counter-part on s3")
            num_pid = self._strip_prefix(pid)
            if num_pid > max_pid:
                max_pid = num_pid

        todo["max"] = max_pid

        return todo

    def apply(self, conn, missing, next_seq):
        batch = []
        for pid in missing:
            num_pid = self._strip_prefix(pid)
            batch.append({"pid": num_pid, "ver": int(missing[pid])})
        if batch:
            logging.debug("Inserting missing sequence information")
            insert = text(f"INSERT INTO {self.schema_name}.artifact_versions (artifact_seq,curr_version_num) VALUES (:pid,:ver)")
            conn.execute(insert,*batch)
        if next_seq is None:
            logging.debug("Skipping creation of provision pool")
        else:
            limits = [next_seq,self.cfg.max_sequence_id]
            logging.debug("Creating provision pool {}".format(repr(limits)))
            self.create_provisioned_pool(*limits)

    def _insert_artifacts_versions(self, missing):
        pass


    def sync(self, dryrun=False):
        """
        Interactive method (use tools.admin) for one-time creation/sync
        of the sequence with S3 content.
        Note this method has been designed to be run multiple time without
        any problems, it will try to sync whatever it can sync (and nothing
        if all is good)
        """
        with self.engine.connect().execution_options(autocommit=False) as conn:
            try:
                conn.execute(text(f"LOCK TABLE {self.schema_name}.artifact_versions IN ACCESS EXCLUSIVE MODE"))
                # holds the whole sequence content (memory /!\)
                from_s3 = self._fetch_from_s3()
                from_db = self._fetch_from_db(conn)
                todo = self.reconcile(from_s3,from_db)
                next_seq = todo['max'] + 1 if todo['max'] else None
                print()
                if todo["missing"]:
                    print("- Add sequence information for:")
                    pprint(todo["missing"])
                if not next_seq is None:
                    print(f"- Create provision pool [{next_seq},{self.cfg.max_sequence_id}]")
                print(f"Do you want to initialize the sequence '{self.cfg.project_prefix}' with the following content? [y/N]")
                choice = input().lower()
                if choice not in ["y","yes"]:
                    print("Abort")
                    return
                print("Let's go...")
                self.apply(conn,todo["missing"],next_seq)
                if dryrun:
                    logging.info("Dry-run mode, rolling back")
                    conn.execute(text("ROLLBACK"))
                else:
                    conn.execute(text("COMMIT"))
            except Exception as exc:  # pylint: disable=broad-except  # whatever happened we need to rollback
                logging.exception(f"Rolling back, error: {exc}")
                conn.execute(text("ROLLBACK"))


    def _call_proc(self, proc_name, **params):
        with self.engine.connect().execution_options(autocommit=True) as conn:
            stmt = f"SELECT {self.cfg.schema_name}.{proc_name}"
            if params:
                stmt += "(" + ",".join([f":{k}" for k in params]) + ")"
                cur = conn.execute(text(stmt),**params)
            else:
                stmt += "()"
                cur = conn.execute(text(stmt))

            res = cur.fetchall()
            assert res and len(res) == 1
            seq = res[0][0]

            return seq

    def __repr__(self):
        return f"<{self.__class__.__name__} " + \
               f"(schema={self.schema_name!r}, " + \
               f"prefix={self.cfg.project_prefix!r}, " + \
               f"context={self.cfg.context!r}, " + \
               f"default={self.cfg.default})>"

    def _format_project_id(self, seq_id):  # pylint: disable=unused-argument  # used during f-string formatting
        project_prefix = self.cfg.project_prefix  # pylint: disable=unused-variable  # used during f-string formatting
        # project_format is an f-string, with "project_prefix" and "seq_id" placeholders
        pid = eval(self.cfg.project_format)  # pylint: disable=eval-used

        return pid

    def _strip_prefix(self, project_id):
        if isinstance(project_id,str):
            # get rid of prefix and convert to integer
            digits = project_id.replace(self.cfg.project_prefix,"")
            try:
                project_id = int(digits)
            except ValueError as exc:
                raise SequenceError(f"Unable to extract a version from {project_id}: {exc}")

        return project_id

    def next_id(self):
        try:
            num = self._call_proc("next_seq")
            return self._format_project_id(num)
        except InternalError as exc:
            # try to see if no pool, we rely on error message, not good but...
            if "No active provisioned pool" in str(exc):
                raise SequencePoolError(exc)
            # not sure what this is...
            raise SequenceError(exc)

    def current_id(self):
        num = self._call_proc("curr_seq")
        if num is None:
            raise SequenceEmptyError("Sequence is empty")
        return self._format_project_id(num)

    def next_version(self, project_id):
        project_id = self._strip_prefix(project_id)
        try:
            return self._call_proc("next_version_seq",pid=str(project_id))
        except InternalError as exc:
            raise SequenceVersionError(f"Unable to get next version for {project_id}: {exc}")

    def current_version(self, project_id):
        project_id = self._strip_prefix(project_id)
        return self._call_proc("curr_version_seq",pid=str(project_id))

    def reset(self, project_id):
        """
        Remove project_id from the sequence
        (admin usage only)
        """
        return self.engine.execute(
            text(f"DELETE FROM {self.schema_name}.artifact_versions WHERE artifact_seq = :project_id"),
            project_id=project_id
        )

    def create_provisioned_pool(self, from_seq, to_seq):
        return self._call_proc("provision_pool",from_seq=from_seq,to_seq=to_seq)

    def create_restricted_pool(self, from_seq, to_seq):
        return self._call_proc("restrict_pool",from_seq=from_seq,to_seq=to_seq)

    def fetch_seq_pools(self, params):
        query = f"""select * from {self.schema_name}.seq_pools WHERE pool_type = :pool_type"""
        if params.get('pool_status'):
            query += """ AND pool_status = :pool_status"""
        query += """ ORDER BY pool_id desc"""
        if params.get('limit'):
            query += " limit :limit"
        results = self.engine.execute(text(query), **params)

        return [dict(r) for r in results]

    def list_provisioned_pools(self, pool_status='ACTIVE', limit=None):
        params = {
            'pool_status': pool_status.upper() if pool_status else None,
            'limit': limit,
            'pool_type': 'PROVISIONED'
        }
        return self.fetch_seq_pools(params)

    def list_restricted_pools(self, pool_status='ACTIVE', limit=None):
        params = {
            'pool_status': pool_status.upper() if pool_status else None,
            'limit': limit,
            'pool_type': 'RESTRICTED'
        }
        return self.fetch_seq_pools(params)


class SequencesMapping(dict):

    def __getitem__(self, key):
        client = super().__getitem__(key)
        seq_switch = sequence_context_name.get()
        if not seq_switch:
            return client
        # if a context is set, we must ensure the requested prefix matches a client context name, if defined.
        # (note we could match the prefix itself, meaning the context variable directly storing the prefix, but
        # multiple sequences can be allowed for one context, eg. PRJ and test-PRJ)
        if client.cfg.context == seq_switch or client.cfg.context is None:
            return client

        raise SequenceContextError(
            f"Sequence context {seq_switch!r} doesn't match client context {client.cfg.context!r}"
        )


class SequenceManager(BackendComponent):

    NAME = "sequence_manager"
    FEATURES = ["sequences", "provisioning"]
    DEPENDS_ON = ["storage_manager"]  # TODO: in ABC and the auto-resolve deps?

    def __init__(self, manager, cfg, storage_provider=None, sequence_client_class=SequenceClient, sql_folder=None):
        self.cfg = cfg.sequences
        self.clients = SequencesMapping()  # per sequence prefix
        self.storage_provider = storage_provider if storage_provider else manager.storage_manager.get_storage
        self._context = None
        for seqcfg in self.cfg.clients:
            assert not seqcfg.project_prefix in self.clients, \
                "Sequence with prefix '{}' already registered".format(seqcfg.project_prefix)
            self.clients[seqcfg.project_prefix] = sequence_client_class(
                seqcfg,
                storage_provider=self.storage_provider,
                sql_folder=sql_folder
            )

    def init(self, purge=False):
        for prefix,client in self.clients.items():
            logging.info(f"Initializing sequence client for prefix {prefix}")
            client.init(purge=purge)

    def switch(self, alias):
        if self._context:
            sequence_context_name.reset(self._context)
            self._context = None
        if not alias is None:
            self._context = sequence_context_name.set(alias)

    @property
    def default_client(self):
        seq_switch = sequence_context_name.get()
        # include context definition in the filter.
        defaults = [
            cl for cl in self.clients.values()
            if hasattr(cl.cfg,"default") and cl.cfg.default
                and cl.cfg.context == seq_switch
        ]
        # find the default client
        # if only client/conf, it's the default, by default. ah ah.
        # there can't be more than one default sequence per context
        if len(defaults) == 0 and len(self.clients) == 1:
            default_client = list(self.clients.values())[0]
        elif len(defaults) != 1:
            raise SequenceError("More than one (or none) default sequence client: {}".format(defaults))
        else:
            default_client = defaults[0]

        assert default_client
        return default_client

    def __repr__(self):
        info = ", ".join([f"(prefix={cl.cfg.project_prefix},default={cl.cfg.default})" for cl in self.clients.values()])
        return f"<self.__class__.__name__ {info}>"

    def _find_client(self, project_id):
        """
        Given project ID including the prefix, find the corresponding
        client manager that prefix.
        """
        client = None
        for prefix in self.clients:  # pylint: disable=consider-using-dict-items  # see client=None logic
            if project_id.startswith(prefix):
                client = self.clients[prefix]
                # check if client can strip prefix. If we have prefixes starting the same, eg. "DS" and "DSv2",
                # with a project_id="DSv200003", "DS" client will match, but won't strip prefix correctly to obtain
                # an integer, so client will rightfully be rejected. "DSv2" will then be picked, correctly this time.
                try:
                    client._strip_prefix(project_id)
                except SequenceError:
                    client = None  # reset, not the right one
                    continue

        if client is None:
            raise SequenceError(f"Unable to find sequence client managing '{project_id}'")

        return client

    def _get_seq_client(self, prefix):
        return self.clients[prefix] if prefix else self.default_client

    def next_project_id(self, prefix=None):
        seq_client = self._get_seq_client(prefix)
        return seq_client.next_id()

    def current_project_id(self, prefix=None):
        seq_client = self._get_seq_client(prefix)
        current_id = seq_client.current_id()
        return current_id

    def next_version(self, project_id):
        seq_client = self._find_client(project_id)
        return seq_client.next_version(project_id)

    def current_version(self, project_id):
        seq_client = self._find_client(project_id)
        return seq_client.current_version(project_id)

