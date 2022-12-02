# pylint: disable=invalid-name  # some constants...
from fastapi import Depends, Query
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field

from artifactdb.utils.enum import Enum
from artifactdb.backend.components.locks import ProjectNotLockedError, RE_INDEXING, MAINTENANCE_REQUESTS
from artifactdb.rest.resources import APIErrorException, APIError, NotAuthenticated, \
                                      Forbidden, ResourceBase


class OperationName(str,Enum):
    re_index = "re-index"
    restart_deployments = "restart-deployments"
    wait_deployments = "wait-deployments"
    restart = "restart"
    wait = "wait"
    scale_deployment = "scale-deployment"


class MaintenanceRequest(BaseModel):
    name:OperationName = Field(...,description="Name of the request")
    args:list = Field(None,description="Optional args list")
    kwargs:dict = Field(None,description="Optional kwargs dict")
    class Config:
        schema_extra = {
            "example": {
                "name": "re-index",
            }
        }


class MaintenanceResource(ResourceBase):

    @classmethod
    def activate_routes(cls):

        ######################
        # MAINTENANCE STATUS #
        ######################

        @cls.router.get("/maintenance/status",
                description="Report global maintenance status (re-indexing, ...)",
                tags=["admin"],
                status_code=200)
        def status(
                lock_manager=Depends(cls.deps.get_lock_manager),
            ):
            maintenance_info = {
                "state": None,
                "requests": [],
                "started_at": None,
                "stage": None,
                "owner": None,
                "info": {}
            }
            info = lock_manager.info(RE_INDEXING)
            if info:
                # global re-indexing status, not reporting aliases a global status
                maintenance_info["state"] = "re-indexing"
                maintenance_info["started_at"] = info.get("created")
                maintenance_info["owner"] = info.get("owner")
                maintenance_info["stage"] = info.get("stage")
                maintenance_info["info"] = info.get("info",{})
            requests = lock_manager.info(MAINTENANCE_REQUESTS)
            if requests:
                maintenance_info["requests"] = requests

            return maintenance_info

        @cls.router.put("/maintenance/requests",
                description="Append a maintenance request (doesn't perform the maintenance, but ask for it)",
                responses={
                    404:{"model":APIError},
                    401:{"model":NotAuthenticated},
                    403:{"model":Forbidden},
                    },
                tags=["admin"],
                status_code=200)
        def request_maintenance(
                maintenance_request:MaintenanceRequest,
                lock_manager=Depends(cls.deps.get_lock_manager),
                _:str = Depends(cls.deps.get_authorizer(roles=["admin"],access_rules=[])),
            ):

            lock_manager.lock(MAINTENANCE_REQUESTS,info=jsonable_encoder(maintenance_request),append=True)
            requests = lock_manager.info(MAINTENANCE_REQUESTS)
            return requests

        @cls.router.delete("/maintenance/requests",
                description="Remove the first maintenance request from the list of requests",
                responses={
                    404:{"model":APIError},
                    401:{"model":NotAuthenticated},
                    403:{"model":Forbidden},
                    },
                tags=["admin"],
                status_code=200)
        def remove_maintenance(
                purge:bool = Query(False,description="Delete all maintenance requests"),
                lock_manager=Depends(cls.deps.get_lock_manager),
                _:str = Depends(cls.deps.get_authorizer(roles=["admin"],access_rules=[])),
            ):

            try:
                # requests are FIFO queue, so return the first elem (pop=0)
                # unless we need to purge them all
                if purge:
                    pop = None
                else:
                    pop = 0
                lock = lock_manager.release(MAINTENANCE_REQUESTS,pop=pop)
                return lock
            except ProjectNotLockedError:
                raise APIErrorException(404,status="error",reason="No maintenance requests found")

