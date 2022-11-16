from fastapi import Depends

from artifactdb.rest.resources import APIErrorException, ResourceBase


class TasksResource(ResourceBase):

    @classmethod
    def activate_routes(cls):
        @cls.router.get("/plugins",
                    description="Returns information about registered plugin tasks for this API",
                    tags=["tasks"])
        def plugins(
            tasks=Depends(cls.deps.get_tasks),
            _: str = Depends(cls.deps.get_authorizer(roles=["admin"], access_rules=[]))
        ):
            if tasks:
                return tasks.cached_tasks_info.get_plugin_tasks()
            else:
                raise APIErrorException(501, status="error", reason="Plugins not enabled.")

        @cls.router.get("/tasks",
                      description="Returns information about all registered tasks for this API",
                      tags=["tasks"])
        def registered_tasks(
            tasks=Depends(cls.deps.get_tasks),
            _: str = Depends(cls.deps.get_authorizer(roles=["admin"], access_rules=[]))
        ):
            if tasks:
                return tasks.cached_tasks_info.get_tasks()
            else:
                raise APIErrorException(501, status="error", reason="Registering tasks not enabled.")
