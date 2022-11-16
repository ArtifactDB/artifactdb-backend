import logging

from celery import Celery

from artifactdb.utils.context import auth_user_context
from artifactdb.rest.auth import backend_user
from .tasks.pubsub import publish_all_indexed_failed, publish_all_indexed
from .tasks.core import index, index_all, purge_not_completed, cancel_task, \
                        purge_expired,clean_stale_projects, \
                        harakiri, create_snapshot, generate_models


class BackendQueue(Celery):

    def __init__(self, cfg, manager_class, *args, **kwargs):
        self.cfg = cfg
        # ref to celery app so manager can send_task()
        self.manager = manager_class(cfg,self)
        # priorities for tasks
        self.task_priorities = {}
        super().__init__(*args,**kwargs)
        if hasattr(self.cfg, "celery"):
            self.config_from_object(self.cfg.celery)


    def cancel(self, task_id):
        return self.control.revoke(task_id)

    def auth(self):
        """
        Set immutable auth user context to special user "celery"
        so the backend has full access to all the data
        """
        # special root user pushed to context so Celery can access all the data
        auth_user_context.set(backend_user)

    def task(self, *args, **kwargs):
        """
        Register task and remember the task priorities. Registering task is done with Celery 'task' method.
        Priorities are stored in memory and used when the task is sended (see 'send_task').
        It allows to set priority for the task which is not possible with Celery object where the priority have to be defined in 'send_task' method.
        If priority parameter is None it uses default value for priority.
        """
        task_name = kwargs['name']
        has_queues_mgr = hasattr(self.manager, "queues") # for backward compatibility with older instances without QueuesManager
        default_priority = has_queues_mgr and self.manager.queues.default_priority
        priority = kwargs.get('priority', default_priority)
        self.task_priorities[task_name] = priority
        logging.info(f"Task '{task_name}' was registered with priority: {priority}.")
        return super().task(*args, **kwargs)

    def send_task(self, task_name, *args, **kwargs):
        """
        Send task with Celery 'send_task' method - the place where priorities can be defined for Celery object.
        If prority is not defined in kwargs it used prority defined in task definition (see 'task' method).
        """
        if 'priority' not in kwargs:
            priority = self.task_priorities[task_name]
            kwargs['priority'] = priority
            logging.info(f"Task '{task_name}' has been sent with priority: {priority}.")
        return super().send_task(task_name, *args, **kwargs)


########
# MAIN #
########

TASKS = [index, index_all, purge_not_completed, cancel_task, purge_expired, clean_stale_projects,
         harakiri, publish_all_indexed, publish_all_indexed_failed, create_snapshot, generate_models]


def get_app(config_provider, manager_class, tasks=None):
    tasks = TASKS if tasks is None else tasks
    cfg = config_provider()
    app = BackendQueue(cfg, manager_class)
    has_queues = hasattr(app.manager, "queues")
    has_plugins = hasattr(app.manager, "plugins")
    has_tasks = hasattr(app.manager, "tasks")

    if has_queues:
        app.manager.queues.prepare_queues()

    # get all plugin repository first
    if has_plugins and app.manager.plugins:
        repos_cfg = cfg.celery.get('repo')
        app.manager.plugins.git_mgr.get_repos(repos_cfg, pull=True)

    for task in tasks:
        func, opts = task
        app.task(func, **opts)
        task_def = {
            "core": True,
            "callable": "{}::{}".format(func.__module__, func.__name__),
            "mandatory": True
        }
        app.manager.tasks.add_callable_info(func, opts, task_def)

    logging.info("Backend manager: {}".format(app.manager))

    if has_plugins and app.manager.plugins:
        app.manager.plugins.register_repository_tasks_safe(pull=True)

    if has_tasks:
        app.manager.tasks.register_config_tasks()
        app.manager.tasks.cached_tasks_info.update()

    return app
