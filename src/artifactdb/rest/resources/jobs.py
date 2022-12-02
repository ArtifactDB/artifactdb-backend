# pylint: disable=invalid-name,redefined-builtin  # `id` as a query arg
import logging

from fastapi import Depends, Query

from artifactdb.backend.utils import serialize_job_result
from artifactdb.rest.resources import APIErrorException, APIError, ResourceBase


class JobsResource(ResourceBase):

    @classmethod
    def activate_routes(cls):

        #######################
        # JOB STATUS & RESULT #
        #######################

        @cls.router.get("/jobs/{id}",
                    description="Return information about given jobs",
                    responses={
                        408:{"model":APIError},
                    },
                    tags=["jobs"],
                    status_code=200)
        def display_job_information(
            id:str = Query(...,description="Job ID"),
            deep:bool = Query(False,description="Fetch information of children tasks (longer)"),
            celery_app = Depends(cls.deps.get_celery_app)
        ):
            # TODO: we can't check whether ID doesn't correspond to a task
            # or not (eg. when a ETA task is received, Flower shows "RECEIVED"
            # but here we'll get a "PENDING", same status as a non-existing task).
            # need to figure out how Flower gets the real status (probably from the broker,
            # not just the results backend of Celery)
            ares = celery_app.AsyncResult(id)
            try:
                return serialize_job_result(ares,deep=deep)
            except Exception as e:  # pylint: disable=broad-except
                logging.exception("Couldn't fetch meta information about task '%s': %s" % (id,e))
                return {"status": ares.status}


        ##############
        # CANCEL JOB #
        ##############

        @cls.router.delete("/jobs/{id}",
                    description="Cancel job (it not started yet)",
                    responses={
                        400:{"model":APIError},
                    },
                    tags=["jobs"],
                    status_code=200)
        def cancel_job(
            id:str = Query(...,description="Job ID"),
            celery_app = Depends(cls.deps.get_celery_app)
        ):
            ares = celery_app.AsyncResult(id)
            job = serialize_job_result(ares)
            if job.get("status") in ["SUCCESS","FAILURE"]:
                raise APIErrorException(status_code=400,status="error",
                                        reason="Unable to cancel job '{}', it already ran".format(id))
            if job.get("status") == "REVOKED":
                raise APIErrorException(status_code=400,status="error",
                                        reason="Unable to cancel job '{}', it's already cancelled".format(id))

            try:
                # ok, now good to go
                # blocking call, but usually fast, and we want to make sure it's treated asap
                celery_app.cancel(id)
                return {"job_id": id, "cancelled": True}

            except Exception as e:
                logging.exception("Unable to cancel job '{}'".format(id))
                raise APIErrorException(status_code=400,status="error",
                                        reason="Unable to cancel job '{}': {}".format(id,e))


