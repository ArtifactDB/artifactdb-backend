import json
import logging
import datetime

import redis

from artifactdb.backend.components import WrappedBackendComponent
from artifactdb.utils.context import auth_user_context


########################
# LOCKS & TRANSACTIONS #
########################

# Special value when indexing all projects (re-indexing)
RE_INDEXING = "__re_indexing__"
# Maintenance requests, list of operation
MAINTENANCE_REQUESTS = "__maintenance_requests__"


class ProjectLockedError(Exception):
    pass

class ProjectNotLockedError(Exception):
    pass

class BackendUnavailableError(Exception):
    pass



class LockManager(WrappedBackendComponent):

    NAME = "lock_manager"
    FEATURES = ["lock",]
    DEPENDS_ON = []

    def wrapped(self):
        if self.main_cfg.lock.backend.type == "redis":
            return RedisLockManager(self.main_cfg.lock)
        else:
            raise NotImplementedError(f"Lock backend type '{self.cfg.backend.type}' not supported")

    def __enter__(self):
        self._wrapped.__enter__()

    def __exit__(self, *args, **kwargs):
        self._wrapped.__exit__(*args,**kwargs)


class LockManagerBase:
    """
    Implement lock management to lock projects.
    Project can be lock according to different stages, such as:
    - "indexing": a project, or project/version is being indexed,
      metadata files fetched from S3 and indexed to Elasticsearch

    Both stages lock the project the same way: no other action can be done
    until the lock is released. Stages give information about current lock
    stage of a project.
    """


class RedisLockManager(LockManagerBase):
    """
    Uses Redis' distributed locks
    """

    ALLOWED_TRANSITIONS = {
        # from...    to...
        "uploading": "completed",
        "completed": "indexing",
    }

    def __init__(self, lock_cfg):
        self.cfg = lock_cfg
        self.redis_client = redis.Redis(**self.cfg.backend.params)
        self.lock_name = "lock-inspect"
        self.blocking_timeout = int(self.cfg.blocking_timeout)
        # TODO: think twice, do we really need a global lock if in the end
        # project are locked? (maybe, at least to store some info, otherwise
        # Redis put some random string, it's just a no-brainer as that point)
        self.global_lock = self.redis_client.lock(self.lock_name,
                                thread_local=False,  # avoid local lock (?)
                                blocking_timeout=self.blocking_timeout)

    def __enter__(self):
        if self.global_lock.acquire():
            logging.info("Global lock acquired ({})".format(self.global_lock))
        else:
            raise BackendUnavailableError("Unable to aquire global lock, already acquired")

    def __exit__(self, typerr, value, traceback):
        # TODO: should we do something with exception info?
        # Note: we don't need to check if it's locked before releasing it because:
        # 1. it would mean there could be a race condition between checking it and releasing it
        # 2. if we're there in __exit__, it means we were there in __enter__ and been able to lock
        #    it which means we have the authoriry (and we're the only one) to release it
        self.global_lock.release()
        logging.info("Global lock released ({})".format(self.global_lock))
        if typerr:
            logging.warning("There was an error while lock was acquired: {} '{}'".format(typerr,value))

    def lock(self, project_id, stage=None, info=None, append=False):
        """
        Acquire a lock over the database and register project_id,
        if not already locked (eg. key exists).
        Some locked transitions are allowed (stage)
        - from "uploading" to "indexing"
        - from "uploading" to "completed"
        - from "completed" to "indexing"
        Can also be used to store generic lock (stage must be None) storing the lock information (metadata)
        in `info`, while `append` can be used to specify the information should be added
        to current lock (as a list).
        """

        with self:
            raw = self.redis_client.get(project_id)
            lock_info = raw and json.loads(raw)
            if stage and lock_info:
                if self.__class__.ALLOWED_TRANSITIONS.get(lock_info["stage"]) == stage:
                    logging.info("Project '{}' locked in stage '{}' ".format(project_id,lock_info["stage"]) +
                                 "but allowing transition to stage '{}'".format(stage))
                else:
                    raise ProjectLockedError("project '{}' is already locked: {}".format(project_id,lock_info))
            # if we get there, project wasn't locked before, or is transitioning
            owner = None
            auth_user = auth_user_context.get()
            if auth_user:
                if auth_user.unixID:  # real user?
                    owner = auth_user.unixID
                else:
                    owner = str(auth_user)

            final_info = {
                "stage": stage,
                "info": info or True,  # make sure to store a truthful value
                "created": datetime.datetime.now().isoformat(),
                "owner": owner,
            }
            if append:
                if lock_info:
                    lock_info.append(final_info)
                    jinfo = json.dumps(lock_info)
                else:
                    jinfo = json.dumps([final_info])
            else:
                jinfo = json.dumps(final_info)
            logging.debug("Locking project '{}' (lock info: {})".format(project_id,repr(final_info)))
            self.redis_client.set(project_id,jinfo)

    def release(self, project_id, force=False, pop:int=None):
        """
        Release project lock. If it wasn't already locked, raises
        a ProjectNotLockedError (force=True to overcome the check)

        `popz` works with loc(...,append=True): if the the lock is
        a list (created with append=True), pop will remove the `pop`th
        item from the list. When the list is empty, the lock key is deleted.
        When `pop` is True (the value True), it means the last element (l.pop()).
        `force` has precedence over `pop`: the whole lock is released, all lock
        info is deleted.
        """
        with self:
            raw = self.redis_client.get(project_id)
            lock_info = raw and json.loads(raw)
            if lock_info and not pop is None:
                pop = -1 if pop is True else pop
                assert isinstance(lock_info,list), lock_info
                elem = lock_info.pop(pop)  # "a base de pop pop pop"...
                if lock_info:
                    # some info remaining => store
                    jinfo = json.dumps(lock_info)
                    self.redis_client.set(project_id,jinfo)
                else:
                    # we cleared the list, nothing left, delete
                    self.redis_client.delete(project_id)
                return elem

            elif lock_info or force is True:
                logging.info("Releasing project '{}' (force={})".format(project_id,force))
                self.redis_client.delete(project_id)
                return lock_info
            else:
                raise ProjectNotLockedError("Project '{}' isn't locked".format(project_id))

    def info(self, project_id=None):
        """
        Return lock information associated to project, or None
        if project isn't locked at all
        """
        info = self.redis_client.get(project_id)
        if info:
            return json.loads(info)
        else:
            return None

    def list(self):
        locked = list(map(lambda b: b.decode(),self.redis_client.keys()))
        return locked

