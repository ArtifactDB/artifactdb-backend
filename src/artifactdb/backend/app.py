import logging
from celery import Celery

from artifactdb.utils.context import auth_user_context
from artifactdb.rest.auth import backend_user
from artifactdb.backend.tasks.pubsub import publish_all_indexed_failed, publish_all_indexed
from artifactdb.backend.tasks.core import index, index_all, purge_not_completed, cancel_task, \
                        purge_expired,clean_stale_projects, \
                        harakiri, create_snapshot, generate_models
from artifactdb.backend.tasks import log_task


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

    def task(self, *args, **opts):
        """
        Register task and remember the task priorities. Registering task is done with Celery 'task' method.
        Priorities are stored in memory and used when the task is sent (see 'send_task').
        It allows to set priority for the task which is not possible with Celery object
        where the priority have to be defined in 'send_task' method.
        If priority parameter is None it uses default value for priority.
        """
        task_name = opts['name']
        # for backward compatibility with older instances without QueuesManager:
        has_queues_mgr = hasattr(self.manager, "queues")
        default_priority = has_queues_mgr and self.manager.queues.default_priority
        priority = opts.get('priority', default_priority)
        self.task_priorities[task_name] = priority
        logging.info(f"Task '{task_name}' was registered with priority: {priority}.")

        # Decorating function with `log_task()` to log every Celery task.
        # Stop decorating in two cases:
        # 1. `args` are empty (case for internal celery call of the `task` method)
        # 2. there is no tasks manager (e.g.: Atlas)
        if len(args) > 0 and hasattr(self.manager, "tasks"):
            update_logs_func = self.manager.tasks.cached_task_logs.update_logs
            logged_function = log_task(update_logs_func, task_name)(args[0])
            args = (logged_function, *args[1:])

        return super().task(*args, **opts)

    def send_task(self, task_name, *args, **kwargs):
        """
        Send task with Celery 'send_task' method - the place where priorities can be defined for Celery object.
        If priority is not defined in kwargs it used priority defined in task definition (see 'task' method).
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
    app.manager.post_manager_init()

    # register core tasks
    for task in tasks:
        func, opts = task
        app.task(func, **opts)
    app.manager.task_definitions = tasks
    app.manager.post_tasks_init()

    app.manager.post_final_init()
    logging.info("Backend manager: {}".format(app.manager))

    return app
