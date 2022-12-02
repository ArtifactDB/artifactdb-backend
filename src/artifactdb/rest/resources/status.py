# pylint: disable=broad-except  # report status no matter what we find
from fastapi import Depends, Request

from artifactdb.rest.resources import ResourceBase


class StatusResource(ResourceBase):

    @classmethod
    def activate_routes(cls):

        @cls.router.get("/status",
                    description="Returns information about global API status",
                    tags=["info"])
        def status(
            request: Request,
            es = Depends(cls.deps.get_es_client),
            celery_app=Depends(cls.deps.get_celery_app),
        ):
            # get some general statuses
            # ES
            try:
                es_stats = es.stats()
                es_status = "ok"
            except Exception as e:
                es_stats = "unknown"
                es_status = "error: {}".format(e)
            # Celery
            try:
                celery_stats = celery_app.control.ping()
                celery_status = "ok"
            except Exception as e:
                celery_stats = "unknown"
                celery_status = "error: {}".format(e)

            swagger_url = str(request.url).rstrip("/")
            swagger_url += request.headers.get("x-forwarded-prefix","/")
            if not swagger_url.endswith("/"):
                swagger_url += "/"
            swagger_url += "__swagger__"

            results = {
                "status": {
                    "elasticsearch": es_status,
                    "celery": celery_status,
                },
                "stats": {
                    "elasticsearch": es_stats,
                    "celery": celery_stats,
                }
            }

            return results


