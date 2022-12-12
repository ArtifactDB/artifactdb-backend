# pylint: disable=unused-argument  # `contract`, passed to /upload endpoint with redirection
import logging

from fastapi import Depends, Query
from fastapi.requests import Request
from starlette.responses import RedirectResponse

from artifactdb.utils.stages import CREATED, VERSION_CREATED, INDEXED, PURGED, FAILED
from artifactdb.rest.resources import APIErrorException, NotAuthenticated, Forbidden, ResourceBase
from artifactdb.backend.components.locks import ProjectLockedError
from artifactdb.backend.components.sequences import SequenceError, SequenceVersionError, \
                                                    SequencePoolError, SequenceEmptyError
from artifactdb.rest.helpers import open_log_request
from .upload import UploadContract


class SequencesResource(ResourceBase):

    @classmethod
    def activate_routes(cls):

        ##########
        # UPLOAD #
        ##########
        @cls.router.post("/projects/upload",
                description="Upload a new project, with an ID automatically provisioned and assigned.",
                tags=["projects"],
                status_code=307)
        async def create_project(
            request:Request,
            contract:UploadContract,
            prefix:str = Query(None,description="Force project ID prefix instead of using default one"),
            seq_mgr=Depends(cls.deps.get_sequence_manager),
            presign_mgr=Depends(cls.deps.get_presign_manager),
            celery_app=Depends(cls.deps.get_celery_app),
            auth:str= Depends(cls.deps.get_authorizer(roles=["uploader","creator"],access_rules=["write_access"])),
        ):
            # provision a new project ID
            try:
                next_pid = seq_mgr.next_project_id(prefix=prefix)
            except KeyError as e:
                raise APIErrorException(
                    status_code=400,
                    status="error",
                    reason=f"Unknown prefix {e}, not matching a known sequence")
            except SequencePoolError as e:
                raise APIErrorException(
                        status_code=400,
                        status="error",
                        reason=f"Can't provision project, pool error: {e}")
            next_version = seq_mgr.next_version(next_pid)
            logging.info(f"Requested new project/version '{next_pid}/{next_version}'")
            # the fully qualified upload endpoint requires "uploader" role by default, if directly accessed.
            # but we have a creator role here, so we need to provide a temporary access to that endpoint
            # for that specific user, for a limited amount of time
            # obtain a legit path is request was proxied, to generate a reachable URL
            path = f"/projects/{next_pid}/version/{next_version}/upload"
            credential_path = presign_mgr.generate("POST",path,user=auth,request=request)
            response = RedirectResponse(url=credential_path)
            # open log stream to collect info about this new project, until "indexed"
            await open_log_request(
                celery_app,
                project_id=next_pid,
                version=next_version,
                # each "close_when" matches the resulting event in "attrs_when_closed"
                close_when=[{"stage": INDEXED},{"stage": FAILED},{"stage": PURGED}],
                attrs_when_closed=[{"stage": CREATED},{"stage": FAILED},{"stage": PURGED}]
            )

            return response


        @cls.router.post("/projects/{project_id}/upload",
                description="Given an existing project ID, upload a new version which automatically provisioned.",
                tags=["projects"],
                status_code=307)
        async def create_version(
            request:Request,
            contract:UploadContract,
            project_id:str = Query(...,description="Project ID",example="GPA2"),
            seq_mgr=Depends(cls.deps.get_sequence_manager),
            lock_manager=Depends(cls.deps.get_lock_manager),
            presign_mgr=Depends(cls.deps.get_presign_manager),
            celery_app=Depends(cls.deps.get_celery_app),
            auth:str= Depends(cls.deps.get_authorizer(roles=["uploader"],access_rules=["write_access"])),
        ):
            # provision a new version within the project
            # acquire a lock on the project, to make sure it's not already locked before
            # moving forward, otherwise we consume versions there, but the redirect will locked
            # and the version will never be used. That said, we can't hold the lock for the time
            # of the whole redirection (we "redirect and forget") so concurrency isn't safe there
            # as another version could be requested between the release of the lock and the process
            # of the redirection. We just do our best. Wort case: some versions are provisioned
            # but never used. It is alright (I think)
            try:
                lock_manager.lock(project_id,stage="uploading")
                lock_manager.release(project_id)#,force=True)
            except ProjectLockedError as e:
                logging.warning("Can't lock project '{}': {}".format(project_id,e))
                lock_info = None
                try:
                    lock_info = lock_manager.info(project_id)
                except Exception as exc:  # pylint: disable=broad-except  # report whatever happened
                    logging.error("Can't fetch lock info: {}".format(exc))
                raise APIErrorException(
                        status_code=423,
                        status="error",
                        reason="Can't provision version, project '{}' is locked: {}".format(project_id,lock_info))

            try:
                next_version = seq_mgr.next_version(project_id)
            except SequenceVersionError:
                raise APIErrorException(
                        status_code=400,
                        status="error",
                        reason=f"Project {project_id} doesn't exist, can't provision version")
            except SequenceError as e:
                raise APIErrorException(
                        status_code=500,
                        status="error",
                        reason=f"Unable to provision version: {e}")

            logging.info(f"Requested new version '{project_id}/{next_version}'")
            path = f"/projects/{project_id}/version/{next_version}/upload"
            credential_path = presign_mgr.generate("POST",path,user=auth,request=request)
            response = RedirectResponse(url=credential_path)
            # open log stream to collect info about this new version, until "indexed"
            await open_log_request(
                celery_app,
                project_id=project_id,
                version=next_version,
                # each "close_when" matches the resulting event in "attrs_when_closed"
                close_when=[{"stage": INDEXED},{"stage": FAILED},{"stage": PURGED}],
                attrs_when_closed=[{"stage": VERSION_CREATED},{"stage": FAILED},{"stage": PURGED}]
            )

            return response

        @cls.router.get("/sequences",
                          description="Returns information about the sequences",
                          responses={
                              401: {"model": NotAuthenticated},
                              403: {"model": Forbidden},
                          },
                          tags=["admin"])
        def sequences(
            seq_mgr=Depends(cls.deps.get_sequence_manager),
            # no access_rules, strictly sticking to roles
            max_pools:int = Query(3,description="Max number of pools to return"),
            _: str = Depends(cls.deps.get_authorizer(roles=['admin'], access_rules=[])),
        ):
            results = []
            for key in seq_mgr.clients:
                seq_client = seq_mgr.clients[key]
                values = {
                    "prefix": seq_client.cfg.project_prefix,
                    "provisioned_pools": seq_client.list_provisioned_pools(pool_status=None, limit=max_pools),
                    "restricted_pools": seq_client.list_restricted_pools(pool_status=None, limit=max_pools),
                }
                try:
                    values.update({"current_seq_id": seq_client.current_id()})
                except SequenceEmptyError as e:
                    logging.exception(f"Sequence is empty, sequence: {seq_client.cfg.project_prefix}")
                    values.update({"current_seq_id": {
                        'status': 'error',
                        'reason': str(e)
                    }})
                results.append(values)
            return results

        @cls.router.get("/sequences/{project_id}/current_version",
                          description="Returns information about the current version of project",
                          responses={
                              401: {"model": NotAuthenticated},
                              403: {"model": Forbidden},
                          },
                          tags=["admin"])
        def sequences_project_current_version(
            project_id:str = Query(...,description="Project ID",example="DS000000001"),
            seq_mgr=Depends(cls.deps.get_sequence_manager),
            # no access_rules, strictly sticking to roles
            _: str = Depends(cls.deps.get_authorizer(roles=['admin'], access_rules=[])),
        ):
            values = {
                'project_id': project_id,
                'current_version': seq_mgr.current_version(project_id)
            }
            return values
