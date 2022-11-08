from fastapi import Depends

from artifactdb.rest.resources import APIErrorException, ResourceBase


class PluginsResource(ResourceBase):

    @classmethod
    def activate_routes(cls):
        @cls.router.get("/plugins",
                    description="Returns information about registered plugins for this API",
                    tags=["plugins"])
        def plugins(
            tasks=Depends(cls.deps.get_tasks),
            _: str = Depends(cls.deps.get_authorizer(roles=["admin"], access_rules=[]))
        ):
            if tasks:
                return tasks.get_registered_tasks()
            else:
                raise APIErrorException(501, status="error", reason="Plugins not enabled.")
