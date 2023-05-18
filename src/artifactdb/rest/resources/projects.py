import logging
from collections import OrderedDict
from typing import List
import datetime

from fastapi import Depends, Query, Body, Request
from pydantic import BaseModel, Field
from typing_extensions import Literal

from artifactdb.backend.components.permissions import NoPermissionFoundError, Permissions
from artifactdb.backend.components.locks import ProjectLockedError
from artifactdb.utils.context import storage_default_client_context
from artifactdb.db.elastic.utils import escape_query_param
from artifactdb.rest.helpers import process_project_update, fetch_project_metadata, get_job_response, \
                                    abort_project_upload, get_sts_credentials
from artifactdb.rest.resources import APIErrorException, APIError, SubmittedJob, NotAuthenticated, \
                                      PrettyJSONResponse, Forbidden, ElasticsearchJSONResponse, \
                                      ResourceBase, AbortReport


class InformationReport(BaseModel):
    permissions: Permissions = Field(None,
                description="Registered permissions set found on S3")
    status: Literal["ok","error"] = Field(...,
                description="Overall permissions status. If 'error', there are differences " + \
                                "between what is registered on S3 and what is actually used in " + \
                                "the index. 'anomalies' and 'actions' should be checked for more")
    anomalies: List[str] = Field(None,description="Anomalies found during checks")
    actions: List[str] = Field(None,description="Potential actions to performed to fix anomalies")

    def to_dict(self):
        # mimick ElasticSearch DSL, this is kind of everywhere in the code
        return self.dict(exclude_none=True)


class LockInformation(BaseModel):
    stage:str = Field(...,description="Arbitrary string describing at which stage a project is locked. " + \
                                      "Known stages, which obey specific rules in terms of transitions to " + \
                                      "one stage to another (see `artifactdb.backend.components.locks.LockManager` for more), " + \
                                      "are: `uploading`, `indexing` and `completed`")
    info:str = Field(None,description="Arbitrary, free-text field to provide more information about the lock")

    class Config:
        schema_extra = {
            "example": {
                "stage" : "manual",
                "info": "Manually locking the project because ...",
            }
        }


# release project lock
def release_project_lock(lock_manager,project_id):
    lock_info = lock_manager.release(project_id, force=True)
    if lock_info:
        return {"status": "unlocked", "lock": lock_info}
    else:
        raise APIErrorException(404, status="error", reason="Project isn't locked")


class ProjectsResource(ResourceBase):

    @classmethod
    def activate_routes(cls):

        ############
        # METADATA #
        ############
        @cls.router.get("/projects/{project_id}/metadata",
                description="Retrieve the metadata for a particular project ID",
                responses={
                    404:{"model":APIError},
                    401:{"model":NotAuthenticated},
                    403:{"model":Forbidden},
                },
                tags=["projects"])
        def get_project_metadata(
            project_id: str = Query(...,description="project ID",example="GPA2"),
            es=Depends(cls.deps.get_es_client),
            _:str = Depends(cls.deps.get_authorizer()),
        ):
            return fetch_project_metadata(project_id,None,es)


        @cls.router.get("/projects/{project_id}/version/{version}/metadata",
                description="Retrieve the metadata for a particular project ID/version. " +
                            '"latest" or "LATEST" can be used to access the latest available version',
                responses={
                    404:{"model":APIError},
                    401:{"model":NotAuthenticated},
                    403:{"model":Forbidden},
                },
                tags=["projects"])
        def get_project_version_metadata(
            project_id: str = Query(...,description="project ID",example="GPA2"),
            version:str =  Query(...,description="version or revision",example="PUBLISHED-1"),
            es=Depends(cls.deps.get_es_client),
            _:str = Depends(cls.deps.get_authorizer()),
        ):
            return fetch_project_metadata(project_id,version,es)


        ############
        # COMPLETE #
        ############
        @cls.router.put("/projects/{project_id}/version/{version}/complete",
                description="Mark given project identified by its ID and version as completed",
                response_description="Completion job is accepted and will be processed as soon as possible",
                responses={
                    404:{"model":APIError},
                    423:{"model":APIError},
                    202:{"model":SubmittedJob},
                    401:{"model":NotAuthenticated},
                    403:{"model":Forbidden},
                    501:{"model":APIError},
                    },
                tags=["projects"],
                status_code=202)
        def mark_project_version_as_completed(
            request:Request,
            permissions:Permissions= Body(None),
            project_id:str = Query(...,description="project ID",example="GPA2"),
            version:str =  Query(...,description="version (not a revision)",
                example="0309292e3494e98290b6d1c2350449315683f381"),
            revision:str = Query(None,description="If provided, revision (acting as an alias) is stored along "
                + "with version (useful when version is somewhat cryptic and human-readable revision is required"),
            purge_job_id = Query(None,description="If provided, the auto-purge task, in charge "
                + "of cleaning uploads in case they're not marked as "
                + "completed, is cancelled"),
            expires_job_id = Query(None,description="Used to flag uploads are transient, job in charge on deleting "
                + "data when it expires"),
            expires_in = Query(None,description="Used to flag uploads are transient, time (iso8601, UTC) at which "
                + "the expiring/cleaning job will run"),
            overwrite_permissions:bool = Query(False,description="If some permissions already exist, given "
                + "permissions will replace them. Default behavior is *not* to replace them"),
            celery_app=Depends(cls.deps.get_celery_app),
            lock_manager=Depends(cls.deps.get_lock_manager),
            _:str = Depends(cls.deps.get_authorizer(roles=["uploader"],access_rules=["write_access"])),
        ):

            return process_project_update(
                celery_app,lock_manager,project_id,version,
                revision=revision,permissions=permissions,
                overwrite_permissions=overwrite_permissions,
                purge_job_id=purge_job_id,
                expires_job_id=expires_job_id,
                expires_in=expires_in,
                request=request
            )


        #########
        # ABORT #
        #########
        @cls.router.put("/projects/{project_id}/version/{version}/abort",
                description="Abort an on-going upload/indexing, resulting in deleting data s3 or documents from ES, releasing any locks, etc...",
                responses={
                    404:{"model":APIError},
                    423:{"model":APIError},
                    401:{"model":NotAuthenticated},
                    403:{"model":Forbidden},
                    501:{"model":APIError},
                    200:{"model":AbortReport},
                    },
                tags=["projects"],
                status_code=200)
        def abort_project_version_upload(
            project_id:str = Query(...,description="project ID",example="GPA2"),
            version:str =  Query(...,description="version (not a revision)",
                example="0309292e3494e98290b6d1c2350449315683f381"),
            purge_job_id = Query(None,description="If provided, the auto-purge task, in charge "
                + "of cleaning uploads in case they're not marked as "
                + "completed, is cancelled"),
            expires_job_id = Query(None,description="Used to flag uploads are transient, job in charge on deleting "
                + "data when it expires"),
            celery_app=Depends(cls.deps.get_celery_app),
            _:str = Depends(cls.deps.get_authorizer(roles=["uploader"],access_rules=["write_access"])),
        ):

            report = abort_project_upload(
                celery_app,project_id,version,
                purge_job_id=purge_job_id,
                expires_job_id=expires_job_id
            )

            return AbortReport(**report)


        ###############
        # INFORMATION #
        ###############

        @cls.router.get("/projects/{project_id}/version/{version}/info",
                description="Get general information for given project ID and version. " + \
                            "Checks are also performed to verify permissions in the " + \
                            "index are in sync with permissions stored on S3. " + \
                            "Anomalies are reported along with actions to potentially fix issues.",
                responses={
                    404:{"model":APIError},
                    423:{"model":APIError},
                    200:{"model":InformationReport},
                    401:{"model":NotAuthenticated},
                    403:{"model":Forbidden},
                    },
                tags=["projects"],
                status_code=200)
        def get_information_for_specific_version(
            project_id:str = Query(...,description="project ID",example="GPA2"),
            version:str =  Query(...,description="version or revision",
                example="0309292e3494e98290b6d1c2350449315683f381"),
            celery_app=Depends(cls.deps.get_celery_app),
            es=Depends(cls.deps.get_es_client),
            _:str = Depends(cls.deps.get_authorizer(roles=["uploader"],access_rules=["read_access"])),
        ):

            # this will query against index, honoring "read access at query time"
            # it user isn't part of read_access defined in permissions, this will return 404
            # IOW, endpoint is protected in terms of authorization
            actual_version = es.convert_revision_to_version(project_id,version)
            if actual_version is None:
                raise APIErrorException(404,status="error",reason="No such project_id/version (or revision)")

            sync_status = "ok"
            anomalies = []
            actions = OrderedDict()  # fixing actions, in order
            pdict = {}
            try:
                pobj = celery_app.manager.permissions_manager.resolve_permissions(project_id,actual_version)
                pdict = pobj.to_dict()
            except NoPermissionFoundError as e:
                anomalies.append("Missing permissions file on s3: {}".format((e)))
                sync_status = "error"
                actions["create permissions"] = True
            # get permissions from all documents in that version, and check they match S3 ones
            project_id = escape_query_param(project_id)
            docs = es.scan("_extra.project_id:{} AND _extra.version:{}".format(project_id,actual_version))
            for doc in docs:
                if not "permissions" in doc["_extra"] or not doc["_extra"]["permissions"]:
                    # not an error, but still weird, a file without permissions (not reachable at all)
                    anomalies.append("{}: missing permissions".format(doc["_extra"]["id"]))
                    # if no permissions found they first need to be created
                    if not pdict:
                        actions["create permissions"] = True
                    # then re-index
                    actions["re-index project/version"] = True
                elif doc["_extra"]["permissions"] != pdict:
                    # permissions are different between ES and S3
                    sync_status = "error"
                    anomalies.append("{}: permissions differ".format(doc["_extra"]["id"]))
                    actions["re-index project/version"] = True

            # None => filtered by pydantic, not []
            return InformationReport(**{
                "permissions": pdict or None,
                "status": sync_status,
                "anomalies": anomalies or None,
                "actions": list(actions.keys()) or None,
            }).to_dict()


        #########
        # LOCKS #
        #########

        @cls.router.get("/projects/{project_id}/lock",
                description="Returns whether the project is locked or not, and lock information. It not locked " + \
                            "404 status code is returned. Note it doesn't check whether the project actually exists or not",
                responses={
                    423:{"model":APIError},
                    401:{"model":NotAuthenticated},
                    403:{"model":Forbidden},
                    404:{"model":APIError},
                    },
                tags=["projects"],
                status_code=200)
        def lock_information(
            project_id:str = Query(...,description="project ID",example="GPA2"),
            lock_manager=Depends(cls.deps.get_lock_manager),
        ):
            lock_info = lock_manager.info(project_id)
            if lock_info:
                return {
                    "status": "locked",
                    "lock": lock_info
                }
            else:
                raise APIErrorException(404,status="error",reason="Project isn't locked")

        @cls.router.get("/projects/lock",
                description="Returns a list of all locked projects",
                responses={
                    423:{"model":APIError},
                    401:{"model":NotAuthenticated},
                    403:{"model":Forbidden},
                    },
                tags=["projects"],
                status_code=200)
        def locked_projects(
            lock_manager=Depends(cls.deps.get_lock_manager),
        ):
            locked = lock_manager.list()
            return {"locked": locked}

        @cls.router.delete("/projects/{project_id}/lock",
                           description="CAUTION: don't use this if you don't know what you're doing... " + \
                                       "Release a locked project. That's usually not required, unless the " + \
                                       "project is remaining locked after, for instance, a failed attempt to " + \
                                       "upload files. Upon success, returns lock info, ie. data hold by the lock, " + \
                                       "for information purpose, or a 404 status if the project wasn't locked.",
                           responses={
                               423: {"model": APIError},
                               401: {"model": NotAuthenticated},
                               403: {"model": Forbidden},
                               404: {"model": APIError},
                           },
                           tags=["admin"],
                           status_code=200)
        def delete_project_lock(
            project_id: str = Query(..., description="project ID", example="GPA2"),
            lock_manager=Depends(cls.deps.get_lock_manager),
            _: str = Depends(cls.deps.get_authorizer(roles=["admin", "uploader"], access_rules=[])),
        ):
            return release_project_lock(lock_manager,project_id)

        @cls.router.post("/projects/{project_id}/lock",
                description="CAUTION: don't use this if you don't know what you're doing... " + \
                            "Lock a given project by its ID, as well as specifying optional " + \
                            "`stage` and `info` field, to describe the reason of the lock. " + \
                            "Locking a project is unusual, the API itself deals with locks as " + \
                            "required, but for any (obsure) reason, such as protecting the project " + \
                            "from any modification, such a lock can be created. Note locks should " + \
                            "be temporary and limited in time, as persistence is done in memory only." + \
                            "Note locking a project requires that it's not already locked, unless it " + \
                            "the transition between one stage to another is respected (eg. " + \
                            "`uploading` to `indexing`). Finally, locking a project may fail if the " + \
                            "global lock couldn't be acquired (eg. another project is being locked)",
                responses={
                    423:{"model":APIError},
                    401:{"model":NotAuthenticated},
                    403:{"model":Forbidden},
                    },
                tags=["admin"],
                status_code=200)
        def lock_project(
            lock_info:LockInformation,
            project_id:str = Query(...,description="project ID",example="GPA2"),
            lock_manager=Depends(cls.deps.get_lock_manager),
            _:str = Depends(cls.deps.get_authorizer(roles=["admin","uploader"],access_rules=[])),
        ):
            if not lock_info:
                lock_info = LockInformation(
                    stage="manual",
                    info="Manunally locked on {}".format(datetime.datetime.now().isoformat())
                )
            try:
                lock_manager.lock(project_id,stage=lock_info.stage,info=lock_info.info)
            except ProjectLockedError:
                raise APIErrorException(
                        status_code=423,
                        status="error",
                        reason="Project '{}' is locked: {}".format(project_id,lock_info))

            return {
                "status": "locked",
                "lock": lock_info,
            }

        #########
        # CLEAN #
        #########

        @cls.router.delete("/projects/{project_id}/version/{version}",
                description="Delete project's version, both from S3 and index. This is " + \
                            "permanent, it deletes everything. No question asked. Return information " + \
                            "about the job in charge of delete/cleaning the version (operation is async). " + \
                            "Note it also removes any locks that may exist for the project.",
                responses={
                    202:{"model":SubmittedJob},
                    404:{"model":APIError},
                    401:{"model":NotAuthenticated},
                    403:{"model":Forbidden},
                },
                tags=["admin"],
                status_code=202)
        def delete_project_version(
            request:Request,
            project_id: str = Query(...,description="project ID",example="GPA2"),
            version:str =  Query(...,description="version or revision",example="PUBLISHED-1"),
            es=Depends(cls.deps.get_es_client),
            celery_app=Depends(cls.deps.get_celery_app),
            _:str = Depends(cls.deps.get_authorizer(roles=["admin","uploader"],access_rules=[])),
        ):
            # find real version, in case a revision was passed
            version = es.convert_revision_to_version(project_id,version) or version
            logging.info("Creating a purge job to expire and delete version {} ".format(version) + \
                         "from project {}".format(project_id))
            expires_job_id = celery_app.send_task(
                "purge_expired",
                kwargs={
                    "project_id": project_id,
                    "version": version,
                    "force": True,
                    "storage_alias": storage_default_client_context.get()
                }
            )
            expires_job_id = str(expires_job_id)
            resp = get_job_response(expires_job_id,request)

            return resp

        @cls.router.get("/projects",
                          description="Returns a list of all projects",
                          responses={
                              423: {"model": APIError},
                              401: {"model": NotAuthenticated},
                              403: {"model": Forbidden},
                          },
                          tags=["projects"],
                          status_code=200)
        def list_projects(
            es=Depends(cls.deps.get_es_client),
            agg_field: str = Query('_extra.version', enum=["_extra.version", "_extra.revision"],
                                   description='Field used to aggregate results per project'),
            size: int = Query(100,ge=1,le=500,description="Number of results per scroll"),
            _: str = Depends(cls.deps.get_authorizer()),
        ):
            results = es.list_projects(per=agg_field,size=size)
            return ElasticsearchJSONResponse(content=results)

        @cls.router.get("/projects/{project_id}/versions",
                          description="Returns a list of all version for given project",
                          responses={
                              423: {"model": APIError},
                              401: {"model": NotAuthenticated},
                              403: {"model": Forbidden},
                          },
                          tags=["projects"],
                          status_code=200)
        def list_project_versions(
            es=Depends(cls.deps.get_es_client),
            agg_field: str = Query('_extra.version', enum=["_extra.version", "_extra.revision"],
                                   description='Field used to aggregate results per project'),
            project_id: str = Query(..., description="project ID", example="GPA2"),
            _: str = Depends(cls.deps.get_authorizer()),
        ):
            project_id = escape_query_param(project_id)
            query = f"_extra.project_id:{project_id}"
            results = es.list_projects(q=query, per=agg_field)

            # return only one project
            if results["hits"]["hits"]:
                values = results["hits"]["hits"][0]
                values["total"] = len(values['aggs'])
                versions = results["hits"]["hits"][0]
                # enrich with latest version information
                results = es.search(query,fields=[agg_field],latest=True)
                # we must have some results since we got hits in the previous aggs
                assert results["hits"]["hits"]
                key = agg_field.split(".")[-1]
                assert key in ("version","revision")
                assert len({h["_source"]["_extra"][key] for h in results["hits"]["hits"]}) == 1
                hit = results["hits"]["hits"][0]  # whatever the hit, there are all in the version
                val = hit["_source"]["_extra"][key]
                versions["latest"] = {agg_field: val}
                return PrettyJSONResponse(versions)

            else:
                raise APIErrorException(404,status="error",reason="No project/versions found")


        ###############
        # CREDENTIALS #
        ###############

        @cls.router.get("/projects/{project_id}/version/{version}/credentials",
                description="Retrieve temporary AWS credentials to download files within " +
                            "the given project_id/version. Credentials expires after `ttl` seconds " +
                            "(default is 1h) and are only valid for this project and version.",
                responses={
                    404:{"model":APIError},
                    401:{"model":NotAuthenticated},
                    403:{"model":Forbidden},
                },
                tags=["projects"])
        async def get_credentials_for_project_version(
            project_id: str = Query(...,description="project ID",example="GPA2"),
            version:str =  Query(...,description="version or revision",example="PUBLISHED-1"),
            ttl:int = Query(3600,description="expiration time, in seconds, after which the credentials expire",
                            ge=900,le=12*60*60),
            es=Depends(cls.deps.get_es_client),
            celery_app=Depends(cls.deps.get_celery_app),
            _:str = Depends(cls.deps.get_authorizer()),
        ):
            # check user can access the metadata, if so, we can serve the credentials
            fetch_project_metadata(project_id,version,es)  # this will raise 401 or 404 if not allowed
            # version can be a revision, but s3 only knows actual version
            version = es.convert_revision_to_version(project_id,version)
            sts = await get_sts_credentials(celery_app.manager,project_id,version,ttl=ttl)

            return sts

