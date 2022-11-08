"""Task manager for registering Celery tasks, setting the routing."""
from artifactdb.backend.components import WrappedBackendComponent
from artifactdb.backend.tasks.manager import TaskManager

class TaskManagerComponent(WrappedBackendComponent):

    NAME = "tasks"
    FEATURES = ["tasks", "staged-tasks", "registered-tasks",]
    DEPENDS_ON = []

    def wrapped(self):
        return TaskManager(
            cfg=self.main_cfg,
            celery_app=self.manager.celery_app
        )
