from fastapi import Depends, Request

from artifactdb.rest.resources import ResourceBase


class InfoResource(ResourceBase):

    @classmethod
    def activate_routes(cls):
        @cls.router.get("/",
                    description="Returns general information about this API",
                    tags=["info"])
        def info(
            request: Request,
            cfg = Depends(cls.deps.get_cfg),
        ):
            forwarded = request.headers.get("x-forwarded-prefix")
            replaced = request.headers.get("x-replaced-path")
            swagger_url = str(request.url).rstrip("/")
            swagger_url += forwarded or replaced or "/"
            if not swagger_url.endswith("/"):
                swagger_url += "/"
            swagger_url += "__swagger__"

            results = {
                "version": cfg.version,
                "image": cfg.image,
                "env": cfg.env,
                "build": cfg.build,
                "artifactdb": cfg.artifactdb,
                "swagger": swagger_url,
                "doc": cfg.doc_url,
                "description": cfg.description,
            }

            return results

