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

            # auth clients: main (the one used in swagger, principal), and alternate/others
            # main is part of known clients, but we want separate category
            others = set(cfg.auth.clients.known).difference({cfg.auth.oidc.client_id})

            results = {
                "name": cfg.name,
                "version": cfg.version,
                "image": cfg.image,
                "env": cfg.env,
                "build": cfg.build,
                "artifactdb": cfg.artifactdb,
                "swagger": swagger_url,
                "doc": cfg.doc_url,
                "description": cfg.description,
                "sequences": [],
                "auth": {
                    "clients": {
                        "main": cfg.auth.oidc.client_id,
                        "others": others,
                    },
                    "well-known": cfg.auth.oidc.well_known.to_dict(),
                }
            }
            # project prefixes
            if hasattr(cfg, "sequence"):
                for seq in cfg.sequence:
                    results["sequences"].append({
                        "prefix": seq["project_prefix"],
                        "default": seq.get("default",False),
                        "test": seq.get("test") or seq["project_prefix"].startswith("test-"),
                    })

            return results

