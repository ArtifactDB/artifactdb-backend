import logging
import json
import os

import dateparser
from celery import chord

from artifactdb.utils.misc import process_coroutine
from artifactdb.utils.context import storage_default_client_context, es_switch_context
from artifactdb.backend.utils import DELETEME_FILE_NAME
from artifactdb.backend.managers import RETRYABLE_EXCEPTIONS
from artifactdb.utils.stages import INDEXED, PURGED, DELETED
from . import task_params


##############
# CORE TASKS #
##############

@task_params(bind=True,name="index",autoretry_for=RETRYABLE_EXCEPTIONS,default_retry_delay=30,private=True)
def index(self, project_id, *args, **kwargs):
    # no publish if coming from index_all, which sets this flag
    skip_publish = kwargs.pop("skip_publish",False)
    storage_alias = kwargs.pop("storage_alias",None)
    ctx = storage_default_client_context.set(storage_alias)
    try:
        key = os.path.join(project_id,DELETEME_FILE_NAME)
        version = kwargs.get("version")
        if not version is None:
            key = os.path.join(project_id, version, DELETEME_FILE_NAME)
        # remove deleteme file if found, It will raise an exception during index process
        # ADB-150: only delete if exists, to prevent add S3 DeleteMarker on version enabled bucket
        if self._app.manager.s3.head(key):
            self._app.manager.s3.delete(key)
        num = self._app.manager.index_project(project_id,*args,**kwargs)
        res = {"project_id": project_id, "indexed_files": num, "version": version}
    finally:
        storage_default_client_context.reset(ctx)
    if not skip_publish:
        publish_logstream(self,project_id=project_id,version=version,message=res,stage=INDEXED)
    return res


@task_params(bind=True,name="index_all",autoretry_for=RETRYABLE_EXCEPTIONS,default_retry_delay=30,private=True)
def index_all(self, project_ids=None, storage_alias=None, *args, **kwargs):  # pylint: disable=unused-argument
    try:
        project_ids = project_ids['project_ids'] if project_ids else self._app.manager.list_projects()
        tasks = []
        for project_id in project_ids:
            task = self._app.tasks["index"]
            tasks.append(task.s(project_id=project_id,skip_publish=True,storage_alias=storage_alias))
    except Exception as e:
        logging.exception(f"Unable to list projects: {e}")
        self._app.send_task("publish_all_indexed_failed",("<task index_all>",))
        raise
    pubtask = self._app.tasks["publish_all_indexed"]
    group_task = chord(tasks)(pubtask.s().set(link_error=['publish_all_indexed_failed']))

    return group_task


@task_params(bind=True,name="purge_not_completed",autoretry_for=RETRYABLE_EXCEPTIONS,default_retry_delay=30)
def purge_not_completed(self, project_id, version=None, storage_alias=None, es_alias=None, force=False):
    logging.warning("Now purging not-completed project/version '{}/{}'".format(project_id,version))
    logging.info(f"Storage alias: {storage_alias}, ES alias: {es_alias}")
    res = {"purged": False, "project_id": project_id, "version": version}
    ctx = storage_default_client_context.set(storage_alias)
    self._app.manager.es.switch(es_alias)
    try:
        result = self._app.manager.es.search_by_project_id(project_id,version)
        if force or not result.get("hits",{}).get("hits",[]):
            # when re-indexing + backend points to a new index, a purge job could
            # find the corresponding documents in ES since it's new index. Yet, these
            # documents may exist in the original index, still served by the frontend for instance.
            # this could end up in deleting files from S3 whereas they must not... IOW this is too
            # dangerous, so let's deactivate that. We'll just place a "tag" in the version folder
            # we were supposed to delete
            tag = self._app.manager.s3.mark_as_deleteme(project_id,version)
            logging.info("Project {}/{} marked as 'to-be-deleted': {}".format(project_id,version,tag))
            res["purged"] = True
            publish_logstream(self,project_id=project_id,version=version,message=res,stage=PURGED)
            return res
        else:
            reason = "Document(s) already indexed, can't delete them"
            logging.warning(reason)
            res["reason"] = reason
            return res
    except Exception as e:
        logging.exception("Error purging non-completed project/version '{}/{}': {}".format(project_id,version,e))
        raise
    finally:
        # remove lock on the project, if any
        storage_default_client_context.reset(ctx)
        self._app.manager.es.switch(None)
        self._app.manager.lock_manager.release(project_id,force=True)


@task_params(bind=True,name="clean_stale_projects",autoretry_for=RETRYABLE_EXCEPTIONS,default_retry_delay=30)
def clean_stale_projects(self):
    date = None
    try:
        if self._app.manager.s3_inventory and self._app.manager.s3_inventory.cfg.use_to_clean_stale_projects:
            results = self._app.manager.s3_inventory.get_inventory_project_files(
                        date="latest",
                        # identify latest ..deleteme files, which are not marked with deletion marked by s3
                        # (would mean the file has been deleted, but still there because bucket versioning
                        # is enabled)
                        query="Key like '%..deleteme' AND IsDeleteMarker = 'false' and IsLatest = 'true'")
            date = results.get('inventory_date')
            results = results.get('results')
        else:
            results = self._app.manager.s3.find_stale_projects()

        if results:
            for result in results:
                content = self._app.manager.s3.download(result.get('Key'))
                try:
                    data = json.loads(content[0])
                except json.decoder.JSONDecodeError as e:
                    logging.error(f"Invalid JSON file for stale project (key={result['Key']}, content='{content}'): {e}")
                    continue
                marked_at = dateparser.parse(data["marked_at"])
                project_id = data["project_id"]
                version = data["version"]  # can we have deletion marker without a version?
                not_before = dateparser.parse(self._app.manager.cfg.s3.delete_stale_projects_older_than)
                if marked_at < not_before:
                    _ = self._app.manager.s3.delete_project(project_id,version)
                    msg = {
                        "message": f"Project {project_id}, version {version} was deleted because it was marked as " \
                            + f"pending-deletion on {marked_at} and reached the date limit {not_before}.",
                        "project_id": project_id,
                        "version": version}
                    publish_logstream(self,project_id=project_id,version=version,message=msg,stage=DELETED)
                else:
                    logging.info(f"Not deleting '{project_id}/{version}' because not old enough " + \
                                  f"(marked_at='{marked_at}' > not_before='{not_before}')")
    except self._app.manager.s3.client.exceptions.NoSuchKey as e:
        logging.info(f"File found in inventory file for date='{date}', but it was deleted from bucket: {e}")
    except Exception as e:
        logging.exception(f"Error deleting stale projects: {e}")
        raise


@task_params(bind=True,name="purge_expired",autoretry_for=RETRYABLE_EXCEPTIONS,default_retry_delay=30)
def purge_expired(self, project_id, version=None, storage_alias=None, es_alias=None, force=False):
    logging.warning("Now deleting expired project/version '{}/{}'".format(project_id,version))
    logging.info(f"Storage alias: {storage_alias}, ES alias: {es_alias}")
    res = {"deleted": False, "project_id": project_id, "version": version}
    ctx = storage_default_client_context.set(storage_alias)
    self._app.manager.es.switch(es_alias)
    try:
        if force:
            # if force is True, Project/Version permanently deleted from the s3 bucket.
            self._app.manager.s3.delete_project(project_id, version)
            logging.info("Project {}/{} deleted".format(project_id, version))
        else:
            # same logic as in purge_not_completed(), we don't delete on s3, just mark them as to-be-deleted
            tag = self._app.manager.s3.mark_as_deleteme(project_id,version)
            logging.info("Project {}/{} marked as 'to-be-deleted' (expired/transient): {}".format(project_id,version,tag))
        # Deleting the ES docs though so it's not visible anymore through the API

        self._app.manager.es.delete_project(project_id, version)
        res["deleted"] = True
        return res
    except Exception as e:
        logging.exception("Unable to delete project/version '{}/{}': {}".format(project_id,version,e))
        raise
    finally:
        # remove lock on the project, if any
        storage_default_client_context.reset(ctx)
        self._app.manager.es.switch(None)  # back to default
        self._app.manager.lock_manager.release(project_id,force=True)


@task_params(bind=True,name="cancel_task")
def cancel_task(self, task_id):
    return self._app.cancel(task_id)


###############
# MAINTENANCE #
###############

@task_params(bind=True,name="create_snapshot",autoretry_for=RETRYABLE_EXCEPTIONS,default_retry_delay=30)
def create_snapshot(self, snapshot_name, indices):
    assert self._app.manager.es.cfg.snapshot, "No existing snapshot configuration"
    repo_name = self._app.manager.es.cfg.snapshot.repository.name
    # blocking (check=done) until finished
    logging.info(f"Creating snapshot '{snapshot_name}' in repository '{repo_name}' containing indices: {indices}")
    return process_coroutine(self._app.manager.es.create_snapshot(snapshot_name,indices,check="done"))


@task_params(bind=True,name="generate_models",autoretry_for=RETRYABLE_EXCEPTIONS,default_retry_delay=30)
def generate_models(self, client=None, preview=False, force=False):
    aliases = [client] if client else self._app.manager.es.clients.keys()
    results = {}
    for alias in aliases:
        logging.info(f"Generating models for client {alias!r} (preview={preview}, force={force})")
        ecl = self._app.manager.es.clients[alias]
        results[alias] = {"class": None, "status": None, "preview": preview}
        try:
            klass = self._app.manager.es.model_provider(ecl.cfg,preview=preview,force=force)
            results[alias]["class"] = klass.__name__
            results[alias]["status"] = "ok"
        except Exception as e:  # pylint: disable=broad-except  # compiling the models can cause many different exceptions
            results[alias]["status"] = "error"
            results[alias]["error"] = str(e)

    logging.info(f"Results: {results}")
    return results


##################
# PUBSUB HELPERS #
##################
# Requires Hermes or another pubsub system, with tasks `publish_event` and `append_log`

def publish_logstream(self, project_id:str, version:str, message:dict, stage:str, use_schema:bool=True):
    kw = {"project_id": project_id, "version": version, "message": message, "stage": stage, "use_schema": use_schema}
    self._app.send_task("publish_event",kwargs=kw)
    self._app.send_task("append_log",kwargs=kw)
    if hasattr(self._app.manager,"plugins"):  # TODO: improve decoupling?
        self._app.manager.tasks.staged_tasks.call_stage(stage, project_id=project_id, version=version)


##################
# INTERNAL TASKS #
##################

def ask_for_restart(self):
    plugins_path = os.environ.get("PLUGINS_PATH")
    if not plugins_path:
        logging.warning("Environment variable: 'PLUGINS_PATH' not defined. The restart of celery will not happen.")
        return
    self._app.send_task("harakiri")
    logging.info("Celery will be restarted soon.")


@task_params(bind=True,name="harakiri",exchange='broadcast_tasks',queue="broadcast_tasks")
def harakiri(self):  # pylint: disable=unused-argument
    logging.warning("Hariki/Seppuku in progress, workers will reload once running tasks are done")
    os.kill(1,1)

