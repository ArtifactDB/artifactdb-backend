"""Task manager for registering Celery tasks, setting the routing."""
import logging
import json
import copy
from datetime import datetime

from artifactdb.utils.misc import get_callable_from_path
from artifactdb.backend.tasks.staged import StagedTasks
from artifactdb.backend.tasks.scheduler import Scheduler
from artifactdb.backend.tasks.utils import is_plugin, prepare_plugin_task, get_repo_for_task
from artifactdb.identifiers.gprn import generate
from artifactdb.backend.caches import get_cache


class MandatoryTaskException(Exception):
    """Exception occurs if mandatory tasks breaks."""


class RegisteredPluginTasks:
    """It is used to store registered tasks from plugin repositories."""

    def __init__(self):
        self.registered_tasks = {}

    def add_repo(self, repo_name, r_cfg):
        """Add repository information."""
        if repo_name not in self.registered_tasks:
            self.registered_tasks[repo_name] = copy.deepcopy(r_cfg)
            self.registered_tasks[repo_name]['tasks'] = []

    def add_task(self, repo_name, task):
        """Register task in the repo with given name."""
        self.registered_tasks[repo_name]['tasks'].append(task)


class TaskManager:
    """Manager for Celery tasks."""

    def __init__(self, cfg, celery_app, settings: dict = None):
        """Parameters:
        - cfg - configuration of ArtifactDB instance
        - celery_app - Celery app
        - settings - dictionary with optional keys:
            + staged_tasks - the object to manage staged tasks or None
        """
        settings = settings or {}

        self.cfg = cfg
        self.celery_app = celery_app
        self.tasks_def = self.cfg.celery.get("tasks", [])

        self.staged_tasks = settings.get("staged_tasks", StagedTasks(celery_app))
        self.registered_tasks = RegisteredPluginTasks()

        store = self.cfg.celery["tasks_store"]  # make the cache obligatory
        self.cache = get_cache(store)

    def update_tasks_info(self):
        """It updates cache variable with registered tasks."""
        if self.cache:
            gprn = generate(
                {"environment": self.cfg.gprn.environment, "service": self.cfg.gprn.service})

            new_val = {
                "updated": str(datetime.now().astimezone()),
                "gprn": gprn,
                "repositories": self.registered_tasks.registered_tasks
            }
            store = self.cfg.celery["tasks_store"]
            self.cache.set(
                store['key'],
                json.dumps(new_val),
                self.cache.cache_ttl)

    def get_registered_tasks(self):
        """Function gets all registered tasks. It gets them from cache."""
        store = self.cfg.celery["tasks_store"]
        return json.loads(self.cache.get(store['key']))

    def register_config_tasks(self):
        """Function registers all task in Celery app, schedules them and prepares routes.
        The tasks definition is taken from configuration file."""
        self.register(self.tasks_def)

    def register(self, tasks_def, repo_cfg=None, path_to_tasks=""):

        for name in tasks_def:
            task_def = tasks_def[name]
            self._register_task_from_config(name, task_def, repo_cfg, path_to_tasks)

        self.schedule_tasks_from_config(tasks_def)
        self.prepare_routes(tasks_def)

    def _register_task_from_config(self, name, task_def, repo_cfg, path_to_tasks):
        callable_str = task_def['callable']
        mandatory = task_def.get("mandatory", False)

        try:
            if is_plugin(task_def) or path_to_tasks:
                if repo_cfg:
                    repo_name = repo_cfg['name']
                else:
                    repo_name = callable_str.split(".")[1]
                    repo_cfg = get_repo_for_task(self.cfg.celery['repo'], task_def)

                self.registered_tasks.add_repo(repo_name, repo_cfg)
                self._register_plugin_task(
                    name,
                    task_def,
                    repo_cfg['url'],
                    repo_name,
                    path_to_tasks,
                    repo_cfg)
            else:
                func, opts = get_callable_from_path(callable_str)
                self.celery_app.task(func, **opts)
            logging.info(f"Registered task: '{name}'.")
        except ModuleNotFoundError:
            self._stop_if_mandatory(
                f"Module does not found when parsing the callable path: '{callable_str}'.",
                mandatory)
        except AttributeError:
            self._stop_if_mandatory(
                f"Function not found in module when parsing the callable path: '{callable_str}'.",
                mandatory)
        except Exception as err: # pylint: disable=broad-except # catch all exception during tasks registration
            logging.exception(err)
            self._stop_if_mandatory(
                f"Error registering task '{name}': {err}", mandatory)

    def schedule_tasks_from_config(self, tasks_def):
        """Schedule tasks from the yaml config file of the ArtifactDB instance."""
        Scheduler.schedule(self.celery_app, tasks_def)

    def prepare_routes(self, tasks_def):
        """Prepare object for Celery routing."""
        broadcast_queue_name = self.celery_app.manager.queues.default_broadcast_queue
        task_routes = self.celery_app.conf.task_routes
        if not tasks_def:
            return

        if task_routes is None:
            task_routes = {}

        for name in tasks_def:
            if tasks_def[name].get('broadcast', False):
                task_routes[name] = {
                    'queue': broadcast_queue_name,
                    'exchange': broadcast_queue_name
                }

        self.celery_app.conf.task_routes = task_routes

    def _register_plugin_task(
            self,
            name,
            task,
            repo_url,
            repo_name,
            path_to_tasks,
            r_cfg):
        """Function register one task from plugin."""
        if not task.get('enabled', True):
            logging.info(f"Task: '{name}' is disabled, skipped")
            return

        task_name = self._get_task_function_name(task)
        is_staged = self.staged_tasks and self.staged_tasks.has_stages(task)
        task_params = task.get("params", {})

        if not is_staged:
            func, opts = prepare_plugin_task(name, task, path_to_tasks, **task_params) # pylint: disable=unpacking-non-sequence # function decorated by @task_params
        else:
            func, opts = prepare_plugin_task(name, task, path_to_tasks, repo_cfg=r_cfg, **task_params) # pylint: disable=unpacking-non-sequence # function decorated by @task_params

        if task_name not in self.celery_app.tasks:
            self.celery_app.task(func, **opts)
            self.registered_tasks.add_task(repo_name, task)
            logging.info(f"Registered task: '{name}' from repo: {repo_url}.")
        else:
            message = f"Task: '{name}'. The name: '{task_name}' belongs to task previously registered in celery app."
            logging.info(message)

        if self.staged_tasks:
            self.staged_tasks.schedule_task_if_staged(name, task)

    def _get_task_function_name(self, task):
        """It returns the name of task function."""
        dummy, str_callable = task['callable'].split("::")
        return str_callable

    def _stop_if_mandatory(self, msg, mandatory):
        """Raise exception if mandatory is True."""
        if mandatory:
            raise MandatoryTaskException(msg)

        logging.warning(msg)
