from fastapi import Depends

from artifactdb.rest.resources import APIErrorException, ResourceBase


class PluginsResource(ResourceBase):

    @classmethod
    def activate_routes(cls):
        @cls.router.get("/plugins",
                    description="Returns information about registered plugins for this API",
                    tags=["plugins"])
        def plugins(
            plugins = Depends(cls.deps.get_plugins_manager),
            _: str = Depends(cls.deps.get_authorizer(roles=["admin"], access_rules=[]))
        ):
            if plugins:
                return plugins.get_tasks()
            else:
                raise APIErrorException(501, status="error", reason="Plugins not enabled.")
