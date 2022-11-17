"""Task manager for registering Celery tasks, setting the routing."""
import logging

from artifactdb.backend.components import WrappedBackendComponent, InvalidComponentError
from artifactdb.backend.tasks.manager import TaskManager

class TaskManagerComponent(WrappedBackendComponent):

    NAME = "tasks"
    FEATURES = ["tasks", "staged-tasks", "registered-tasks",]
    DEPENDS_ON = []

    def wrapped(self):
        try:
            return TaskManager(
                cfg=self.main_cfg,
                celery_app=self.manager.celery_app
            )
        except AttributeError as e:
            raise InvalidComponentError(str(e))

    def post_tasks_init(self):
        logging.info(f"Registering callable information for tasks ({self.__class__} post-tasks-init)")
        for task in self.manager.task_definitions:
            func, opts = task
            task_def = {
                "core": True,
                "callable": "{}::{}".format(func.__module__, func.__name__),
                "mandatory": True
            }
            self.manager.tasks.add_callable_info(func, opts, task_def)

    def post_final_init(self):
        logging.info(f"Registering config-based tasks ({self.__class__} post-final-init)")
        self.manager.tasks.register_config_tasks()
        self.manager.tasks.cached_tasks_info.update()

