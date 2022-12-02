from fastapi import Depends, Query, Body, Request

from artifactdb.backend.components.permissions import NoPermissionFoundError, Permissions
from artifactdb.rest.helpers import process_project_update, open_log_request
from artifactdb.utils.stages import PERMISSIONS_CHANGED, INDEXED, FAILED
from artifactdb.rest.resources import APIErrorException, APIError, SubmittedJob, NotAuthenticated, \
                                      Forbidden, ResourceBase


class PermissionsResource(ResourceBase):

    @classmethod
    def activate_routes(cls):

        ###################
        # GET PERMISSIONS #
        ###################

        @cls.router.get("/projects/{project_id}/permissions",
                description="Return project-level permissions, if any. No checks are performed " + \
                            "(use endpoint with version for that)",
                responses={
                    404:{"model":APIError},
                    423:{"model":APIError},
                    200:{"model":Permissions},
                    401:{"model":NotAuthenticated},
                    403:{"model":Forbidden},
                    },
                tags=["permissions"],
                status_code=200)
        def get_project_level_permissions(
            project_id:str = Query(...,description="project ID",example="GPA2"),
            celery_app=Depends(cls.deps.get_celery_app),
            _:str = Depends(cls.deps.get_authorizer(roles=["uploader"],access_rules=["read_access"],read_eval_time="request")),
        ):
            pobj = None
            try:
                pobj = celery_app.manager.permissions_manager.resolve_permissions(project_id,version=None)
            except NoPermissionFoundError:
                raise APIErrorException(404,status="error",reason="No project-level permissions found")

            return pobj.permissions


        @cls.router.get("/projects/{project_id}/version/{version}/permissions",
                description="Return permission for given project ID and version",
                responses={
                    404:{"model":APIError},
                    423:{"model":APIError},
                    200:{"model":Permissions},
                    401:{"model":NotAuthenticated},
                    403:{"model":Forbidden},
                    },
                tags=["permissions"],
                status_code=200)
        def get_permissions_for_specific_version(
            project_id:str = Query(...,description="project ID",example="GPA2"),
            version:str =  Query(...,description="version or revision"),
            celery_app=Depends(cls.deps.get_celery_app),
            es=Depends(cls.deps.get_es_client),
            _:str = Depends(cls.deps.get_authorizer(roles=["uploader"],access_rules=["read_access"],read_eval_time="request")),
        ):
            actual_version = es.convert_revision_to_version(project_id,version)
            if actual_version is None:
                # if check during read_eval_time="request" allowed user to get there but now fails
                # it means the ES query didn't find the user as owners/viewers, which means
                # permissions on S3 are desync with those in the index
                raise APIErrorException(404,status="error",reason="No such project_id/version (or revision). " + \
                        f"Check /projects/{project_id}/version/{version}/info" + \
                        "for permissions anomalies")
            pobj = None
            try:
                pobj = celery_app.manager.permissions_manager.resolve_permissions(project_id,actual_version)
            except NoPermissionFoundError:
                raise APIErrorException(404,status="error",reason="No project-level or version-specific permissions found")

            return pobj.permissions


        ######################
        # MODIFY PERMISSIONS #
        ######################

        @cls.router.put("/projects/{project_id}/version/{version}/permissions",
                description="Set permissions for a specific version in the project",
                response_description="Job is accepted, permissions will be created and project/version " + \
                                     "re-indexed to reflect this change, as soon as possible",
                responses={
                    404:{"model":APIError},
                    423:{"model":APIError},
                    400:{"model":APIError},
                    202:{"model":SubmittedJob},
                    401:{"model":NotAuthenticated},
                    403:{"model":Forbidden},
                    501:{"model":APIError},
                    },
                tags=["permissions"],
                status_code=202)
        async def set_permissions_for_specific_version(
            request:Request,
            permissions:Permissions = Body(...),
            project_id:str = Query(...,description="project ID",example="GPA2"),
            version:str =  Query(...,description="version or revision",
                example="0309292e3494e98290b6d1c2350449315683f381"),
            celery_app=Depends(cls.deps.get_celery_app),
            es=Depends(cls.deps.get_es_client),
            lock_manager=Depends(cls.deps.get_lock_manager),
            _:str = Depends(cls.deps.get_authorizer(roles=["uploader"],access_rules=["write_access"])),
        ):

            # check scope if explicitely set by iser
            if "scope" in permissions.__fields_set__ and permissions.scope != "version":
                raise APIErrorException(400,status="error",
                        reason="Permissions scope must be 'version', not '{}'".format(permissions.scope))

            # force scope=version for this endpoint
            permissions.scope = "version"

            actual_version = es.convert_revision_to_version(project_id,version)
            if actual_version is None:
                raise APIErrorException(404,status="error",reason="No such project_id/version (or revision)")

            # open log stream to collect info about permission changes, until "indexed"
            await open_log_request(
                celery_app,
                project_id=project_id,
                version=actual_version,
                # each "close_when" matches the resulting event in "attrs_when_closed"
                close_when=[{"stage": INDEXED},{"stage": FAILED}],
                attrs_when_closed=[{"stage": PERMISSIONS_CHANGED},{"stage": FAILED}]
            )

            # if they already exist, we force the replacement, as this endpoint is made for explicit permissions updates
            return process_project_update(
                celery_app,lock_manager,project_id,version=actual_version,
                permissions=permissions,overwrite_permissions=True,
                request=request
            )


        @cls.router.put("/projects/{project_id}/permissions",
                description="Set permissions at project level (permissions applied by default if no permissions " + \
                            "defined for a version)",
                response_description="Job is accepted, permissions will be created and the whole project " + \
                                     "re-index to reflect this change, as soon as possible",
                responses={
                    404:{"model":APIError},
                    423:{"model":APIError},
                    400:{"model":APIError},
                    202:{"model":SubmittedJob},
                    401:{"model":NotAuthenticated},
                    403:{"model":Forbidden},
                    501:{"model":APIError},
                    },
                tags=["permissions"],
                status_code=202)
        async def set_default_permissions_for_project(
            request:Request,
            permissions:Permissions = Body(...),
            project_id:str = Query(...,description="project ID",example="GPA2"),
            celery_app=Depends(cls.deps.get_celery_app),
            lock_manager=Depends(cls.deps.get_lock_manager),
            _:str = Depends(cls.deps.get_authorizer(roles=["uploader"],access_rules=["write_access"]))
        ):

            # check scope if explicitely set by iser
            if "scope" in permissions.__fields_set__ and permissions.scope != "project":
                raise APIErrorException(400,status="error",
                        reason="Permissions scope must be 'project', not '{}'".format(permissions.scope))
            permissions.scope = "project"

            # open log stream to collect info about permission changes, until "indexed"
            await open_log_request(
                celery_app,
                project_id=project_id,
                # each "close_when" matches the resulting event in "attrs_when_closed"
                close_when=[{"stage": INDEXED},{"stage": FAILED}],
                attrs_when_closed=[{"stage": PERMISSIONS_CHANGED},{"stage": FAILED}]
            )

            # if they already exist, we force the replacement, as this endpoint is made for explicit permissions updates
            return process_project_update(
                celery_app,lock_manager,project_id,version=None,
                permissions=permissions,overwrite_permissions=True,
                request=request
            )


        ######################
        # DELETE PERMISSIONS #
        ######################

        @cls.router.delete("/projects/{project_id}/version/{version}/permissions",
                description="Delete permissions for given project ID and version. Warning: you may loose ownership " + \
                            "of this version and may not able to access data or modify permissions anymore",
                response_description="Job is accepted, permissions will be deleted and project/version " + \
                                     "re-index to reflect this change, as soon as possible",
                responses={
                    404:{"model":APIError},
                    423:{"model":APIError},
                    202:{"model":SubmittedJob},
                    401:{"model":NotAuthenticated},
                    403:{"model":Forbidden},
                    },
                tags=["permissions"],
                status_code=202)
        async def delete_permissions_for_specific_version(
            request:Request,
            project_id:str = Query(...,description="project ID",example="GPA2"),
            version:str =  Query(...,description="version or revision",
                example="0309292e3494e98290b6d1c2350449315683f381"),
            es=Depends(cls.deps.get_es_client),
            celery_app=Depends(cls.deps.get_celery_app),
            lock_manager=Depends(cls.deps.get_lock_manager),
            _:str = Depends(cls.deps.get_authorizer(roles=["uploader"],access_rules=["write_access"])),
        ):

            actual_version = es.convert_revision_to_version(project_id,version)
            if actual_version is None:
                raise APIErrorException(404,status="error",reason="No such project_id/version (or revision)")

            # open log stream to collect info about permission changes, until "indexed"
            await open_log_request(
                celery_app,
                project_id=project_id,
                version=actual_version,
                # each "close_when" matches the resulting event in "attrs_when_closed"
                close_when=[{"stage": INDEXED},{"stage": FAILED}],
                attrs_when_closed=[{"stage": PERMISSIONS_CHANGED},{"stage": FAILED}]
            )

            return process_project_update(
                celery_app,lock_manager,project_id,version=actual_version,
                delete_permissions=True,request=request
            )

        @cls.router.delete("/projects/{project_id}/permissions",
                description="Delete permissions at project level. <span style='color:red'>Warning:</span> " + \
                            "you may loose ownership of the whole project and not be able to access data anymore. " + \
                            "The only way then would be to ask an admin, you " + \
                            "<a href='https://i.redd.it/ckrumc78bl151.jpg'>don't</a> wanna do that...",
                response_description="Job is accepted, permissions will be deleted and the whole project " + \
                                     "re-index to reflect this change, as soon as possible",
                responses={
                    404:{"model":APIError},
                    423:{"model":APIError},
                    202:{"model":SubmittedJob},
                    401:{"model":NotAuthenticated},
                    403:{"model":Forbidden},
                    },
                tags=["permissions"],
                status_code=202)
        async def delete_project_level_permissions(
            request:Request,
            project_id:str = Query(...,description="project ID",example="GPA2"),
            celery_app=Depends(cls.deps.get_celery_app),
            lock_manager=Depends(cls.deps.get_lock_manager),
            _:str = Depends(cls.deps.get_authorizer(roles=["uploader"],access_rules=["write_access"])),
        ):
            # open log stream to collect info about permission changes, until "indexed"
            await open_log_request(
                celery_app,
                project_id=project_id,
                # each "close_when" matches the resulting event in "attrs_when_closed"
                close_when=[{"stage": INDEXED},{"stage": FAILED}],
                attrs_when_closed=[{"stage": PERMISSIONS_CHANGED},{"stage": FAILED}]
            )

            return process_project_update(
                celery_app,lock_manager,project_id,version=None,
                delete_permissions=True,request=request
            )

