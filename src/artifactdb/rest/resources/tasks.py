# pylint: disable=unused-argument  # `auth` parameter for authorization
"""Definition of API endpoints for tasks: plugin and core."""
from typing import Dict
from fastapi import Depends, Request
from pydantic import BaseModel, Field
from artifactdb.rest.resources import ResourceBase, APIErrorException
from artifactdb.rest.helpers import get_job_response

SUPERUSER_ROLES = ["admin"]


class TaskParams(BaseModel):
    name: str = Field(..., description="Task name")
    params: Dict = Field(None, description="Parameters of the task.")

    class Config:
        schema_extra = {
            "example": {
                "name": "compare_s3_es_v2",
                "params": {
                    "es_context": "v2"
                }
            }
        }


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
            if tasks and tasks.cached_tasks_info:
                return tasks.cached_tasks_info.get_plugin_tasks()
            else:
                raise APIErrorException(501, status="error", reason="Plugins (or tasks) component not enabled.")

        @cls.router.get("/tasks",
                      description="Returns information about all registered tasks for this API",
                      tags=["tasks"])
        def registered_tasks(
            tasks=Depends(cls.deps.get_tasks),
            _: str = Depends(cls.deps.get_authorizer(roles=["admin"], access_rules=[]))
        ):
            if tasks and tasks.cached_tasks_info:
                return tasks.cached_tasks_info.get_tasks()
            else:
                raise APIErrorException(501, status="error", reason="Tasks component not enabled.")


        #############
        # CALL TASK #
        #############

        @cls.router.put("/task/run",
                        description="Run the task with given parameters.",
                        tags=["tasks"])
        def call_task(
                request: Request,
                task_params: TaskParams = None,
                celery_app=Depends(cls.deps.get_celery_app),
                auth: str = Depends(cls.deps.get_authorizer()),
        ):
            try:
                task_name = task_params.name
                celery_task = celery_app.tasks[task_name]
            except KeyError:
                raise APIErrorException(404, status="error", reason=f"Unknown task name: {task_name}")

            is_superuser = set(auth.roles).intersection(SUPERUSER_ROLES)
            if celery_task.private and not is_superuser:
                raise APIErrorException(401, status="error",
                                        reason=f"Private task: '{task_name}' cannot be called.")

            task_roles = hasattr(celery_task, "roles") and celery_task.roles or []
            allowed_roles = set(SUPERUSER_ROLES).union(set(task_roles))
            allowed_to_call_task = set(auth.roles).intersection(allowed_roles)

            if not allowed_to_call_task:
                raise APIErrorException(403, status="error",
                                        reason=f"Required roles to call the task: '{task_name}': {allowed_roles}.")

            res = celery_app.send_task(task_name, kwargs=task_params.params)
            resp = get_job_response(res.id, request)
            return resp


        #############
        # CALL LOGS #
        #############

        @cls.router.get("/tasks/logs",
                    description="Returns last logs for all Celery tasks.",
                    tags=["tasks"])
        def tasks_logs(
            tasks=Depends(cls.deps.get_tasks),
            _: str = Depends(cls.deps.get_authorizer(roles=["admin"], access_rules=[])),
            auth: str = Depends(cls.deps.get_authorizer())
        ):
            if tasks and tasks.cached_task_logs:
                return tasks.cached_task_logs.get_logs()
            else:
                error_msg = "Unable to return tasks logs, this feature is not enabled or properly configured."
                raise APIErrorException(501, status="error", reason=error_msg)


        @cls.router.put("/task/logs/reset",
                        description="Reset the tasks log storage.",
                        tags=["tasks"])
        def tasks_logs_reset(
            tasks=Depends(cls.deps.get_tasks),
            _: str = Depends(cls.deps.get_authorizer(roles=["admin"], access_rules=[])),
            auth: str = Depends(cls.deps.get_authorizer())
        ):
            if tasks and tasks.cached_task_logs:
                tasks.cached_task_logs.reset()
                return {}
            else:
                raise APIErrorException(501, status="error", reason="Task logs component not enabled.")
