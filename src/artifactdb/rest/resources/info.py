from fastapi import Depends, Request

from artifactdb.rest.resources import ResourceBase
from artifactdb.rest.helpers import generate_swagger_url

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
            swagger_url = generate_swagger_url(request)
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
                },
                "storage": cfg.storage.to_dict(),
            }
            # project prefixes
            legacy = getattr(cfg,"sequence",[])
            sequences = hasattr(cfg,"sequences") and [s.to_dict() for s in cfg.sequences.clients] or legacy
            for seq in sequences:
                results["sequences"].append({
                    "prefix": seq["project_prefix"],
                    "default": seq.get("default",False),
                    "test": seq.get("test") or seq["project_prefix"].startswith("test-"),
                })

            return results

