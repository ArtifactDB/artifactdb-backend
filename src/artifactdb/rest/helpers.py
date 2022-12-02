import logging
from urllib.parse import urljoin

from elasticsearch.exceptions import RequestError

from artifactdb.backend.components.permissions import NoPermissionFoundError
from artifactdb.backend.components.locks import ProjectLockedError
from artifactdb.db.elastic import DataInconsistencyException
from artifactdb.utils.misc import get_root_url
from artifactdb.utils.stages import FAILED
from artifactdb.identifiers.gprn import build as build_gprn
from artifactdb.rest.resources import APIErrorException, PrettyJSONResponse, ElasticsearchJSONResponse, \
                                 SubmittedJob


def fetch_project_metadata(project_id, version, es, legacy=False):
    try:
        rawresults = es.search_by_project_id(project_id, version)
    except (DataInconsistencyException,RequestError) as e:
        raise APIErrorException(status_code=400,status="error", reason=str(e))
    if not rawresults["hits"]["hits"]:
        raise APIErrorException(status_code=404, status="error", reason="No such project/version")
    if legacy:
        results = {}
        for res in rawresults["hits"]["hits"]:
            results[res["_source"]["path"]] = res["_source"]
        return results
    else:
        return ElasticsearchJSONResponse(content=rawresults)


def get_job_response(job_id, request=None):
    path = "/jobs/%s" % job_id
    job_url = path
    if request:
        root_url = get_root_url(request)
        job_url = urljoin(root_url,path)

    content = SubmittedJob(status="accepted",job_url=job_url,job_id=job_id,path=path)
    headers = {"link": f"<{content.job_url}>; rel=status"}
    return PrettyJSONResponse(status_code=202,content=content.dict(), headers=headers)


def process_project_complete(
    celery_app, project_id, version, revision=None,
    permissions=None, delete_permissions=False,
    overwrite_permissions=False, purge_job_id=None,
    expires_job_id=None, expires_in=None,
    request=None
):
    permissions = permissions if permissions is not None else {}
    index_kwargs = {"project_id": project_id,"version": version, "revision": revision}
    perm_manager = celery_app.manager.permissions_manager
    # sanity check
    if overwrite_permissions and not permissions:
        raise APIErrorException(status_code=400,status="error",
                reason="overwrite is True but no permissions passed")
    if delete_permissions and permissions:
        raise APIErrorException(status_code=400,status="error",
                reason="No permissions required when deleted them")
    if permissions and not perm_manager.is_valid(permissions):
        raise APIErrorException(
            status_code=400,
            status="error",
            reason="At least one of permission is not valid.")
    # check permissions scope,overwrite,delete flags to decide how to apply these permissions
    if delete_permissions:
        # delete from S3, don't pass any permissions set to final task creation
        # so metadata is re-index to reflect permissions changes.
        logging.info("Deleting permissions for {}/{}".format(project_id,version))
        perm_manager.delete_permissions(project_id,version)
    elif permissions:
        if overwrite_permissions:
            index_kwargs["permissions"] = permissions
        else:
            # we need to check if some already exist, explicitely for the
            # combination project/version/scope
            # /!\ this is a blocking call...
            try:
                pobj = perm_manager.resolve_permissions(project_id,version,
                                                        scope=permissions.get("scope"))
                logging.info("Permissions instructions for {}/{} ignored because ".format(project_id,version) + \
                             "of existing permissions {}".format(pobj))
            except NoPermissionFoundError:
                # no existing permissions found, so we'll use the passed ones
                index_kwargs["permissions"] = permissions
    else:
        # nothing to do there, no permissions specified
        pass
    if purge_job_id:
        logging.info("Cancelling auto-purge task '%s'" % purge_job_id)
        res = celery_app.send_task("cancel_task",kwargs={"task_id": purge_job_id})
        logging.debug("Task set to cancel purge task: %s" % res)
    if expires_job_id:
        logging.info("Upload is transient, expiring at {} (expires_job_id={})".format(expires_in,expires_job_id))
        index_kwargs["transient"] = {"expires_job_id": expires_job_id, "expires_in": expires_in}
    # main indexing task
    res = celery_app.send_task("index",kwargs=index_kwargs)
    resp = get_job_response(res.id,request)

    return resp


def process_project_update(
    celery_app, lock_manager, project_id, version, revision=None,
    permissions=None, overwrite_permissions=False, delete_permissions=False,
    purge_job_id=None, expires_job_id=None, expires_in=None, request=None
):
    # try to lock the project as "completed"
    try:
        lock_manager.lock(project_id,stage="completed")
        # if we get there, it means we could lock it
        # so we're allowed to proceed further
        # `permissions` can be partial, we need to "complete" them
        if permissions:
            permissions = celery_app.manager.permissions_manager.complete_permissions(project_id,version,permissions)
        permissions_dict = permissions.to_dict() if permissions else {}
        return process_project_complete(
            celery_app,project_id,version,revision=revision,
            permissions=permissions_dict,
            delete_permissions=delete_permissions,
            overwrite_permissions=overwrite_permissions,
            purge_job_id=purge_job_id,
            expires_job_id=expires_job_id,
            expires_in=expires_in,
            request=request
        )
    except ProjectLockedError as e:
        logging.warning("Can't lock project '{}': {}".format(project_id,e))
        lock_info = None
        try:
            # enrich error with some lock information
            lock_info = lock_manager.info(project_id)
        except Exception as exc:  # pylint: disable=broad-except  # whatever happens (maybe TODO:?)
            logging.error("Can't fetch lock info: {}".format(exc))
        raise APIErrorException(
                status_code=423,
                status="error",
                reason="Project '{}' is locked: {}".format(project_id,lock_info))
    except Exception as e:
        # if we get there, we could lock the project, but an error occured
        # while submitting the task to the backend. We need to release the lock
        # otherwise it's dead...
        logging.exception("Error while processing complete request for project_id {}: {}".format(project_id,e))
        lock_manager.release(project_id)  # no force=True needed if we could lock it...
        raise


def abort_project_upload(
    celery_app, project_id, version,
    purge_job_id=None, expires_job_id=None
):
    assert not project_id is None, "'project_id' must be set"
    assert not version is None, "'version' must be set"
    logging.info(f"Aborting upload for project '{project_id}/{version}'")
    result = {
        "project_id": project_id,
        "version": version,
        "cancel_purge_job_id": None,
        "cancel_expires_job_id": None,
        "unlocked": None,
    }
    if purge_job_id:
        logging.info(f"Cancelling purge job '{purge_job_id}'")
        res = celery_app.send_task("cancel_task",kwargs={"task_id": purge_job_id})
        result["cancel_purge_job_id"] = res.id
    if expires_job_id:
        logging.info(f"Cancelling expire job '{expires_job_id}'")
        res = celery_app.send_task("cancel_task",kwargs={"task_id": expires_job_id})
        result["cancel_expires_job_id"] = res.id
    # List s3 files to report them in the results, make sure to list even if deleteme is present
    logging.info("Deleting files from s3")
    celery_app.manager.s3.delete_project(project_id,version)
    # Deleting indexed documents if any to be consistent
    celery_app.manager.es.delete_project(project_id,version)
    # Finally unlock the project, as necessary
    lock_info = celery_app.manager.lock_manager.release(project_id,force=True)
    result["unlocked"] = lock_info
    # At the very end append_log with stage FAILED
    celery_app.send_task("append_log", kwargs = {"project_id": project_id, "version": version, "message": "Project upload aborted", "stage": FAILED})
    return result


async def get_sts_credentials(manager, project_id, version, ttl=None, mode="readonly"):
    # ARN with wildcards: allows upload to anything under project/version
    arn = manager.s3.get_s3_arn(manager.s3.bucket_name,project_id,version,"*")
    resources = [{"arn": arn, "mode": mode}]
    token = await manager.keycloak.get_access_token()
    sts = await manager.almighty.generate_sts_credentials(token,resources,ttl=ttl)
    # add bucket name and s3 prefix, convenient on client side
    sts["bucket"] = manager.s3.bucket_name
    sts["prefix"] = f"{project_id}/{version}/"

    return sts

async def open_log_request(celery_app, project_id, version=None, subject="", close_when=None, attrs_when_closed=None, use_schema=True):
    gprn = build_gprn(celery_app.manager.cfg.gprn,project_id,version)
    msg = f"{gprn} (close_when={close_when},attrs_when_closed={attrs_when_closed}"
    if not celery_app.manager.cfg.hermes.publisher:
        # we can open log in two ways: here or with task (where task is independent of this function)
        # so we have to make this check twice (here and in open_log task)
        logging.info("*Not* opening log stream because publishing isn't activated: {}".format(msg))
        return
    logging.info("Opening stream {}".format(msg))
    try: # 3 times if there is still an exception thrown, then send open_log task to celery
        result = await celery_app.manager.open_log(gprn, project_id, version, subject, close_when, attrs_when_closed, use_schema)
        return result
    except Exception as e:  # pylint: disable=broad-except
        logging.warning(f"Unable to open log stream with open_log_request function, retrying with open_log task. Exception: {e}")
        task_id = celery_app.send_task("open_log",
                                        kwargs={"project_id": project_id, "version": version,
                                                "close_when": close_when,
                                                "attrs_when_closed": attrs_when_closed})
        return task_id

