from fastapi import Depends

from artifactdb.rest.resources import NotAuthenticated, Forbidden, ResourceBase


class ConfigResource(ResourceBase):

    @classmethod
    def activate_routes(cls):
        @cls.router.get("/config",
                    description="Returns active configuration (S3 bucket, ElasticSearch hosts, etc...)",
                    responses={
                        401:{"model":NotAuthenticated},
                        403:{"model":Forbidden},
                        },
                    tags=["admin"])
        def config(
            cfg=Depends(cls.deps.get_cfg),
            # no access_rules, strictly sticking to roles
            _:str = Depends(cls.deps.get_authorizer(roles=["admin"],access_rules=[])),
        ):
            dcfg = cfg.to_dict()
            dcfg.get("storage",{}).pop("__clients__",None)  # internal, copy of original client config,
                                                            # not meant to be exposed
            return dcfg

