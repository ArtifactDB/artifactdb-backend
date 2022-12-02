"""Task manager for registering Celery tasks, setting the routing."""
import logging
import json
import copy
from datetime import datetime

from artifactdb.utils.misc import get_callable_from_path, get_callable_info
from artifactdb.backend.tasks.staged import StagedTasks
from artifactdb.backend.tasks.scheduler import Scheduler
from artifactdb.backend.tasks.utils import is_plugin, prepare_plugin_task, get_repo_for_task, get_plugin_callable
from artifactdb.identifiers.gprn import generate
from artifactdb.backend.caches import get_cache


class MandatoryTaskException(Exception):
    """Exception occurs if mandatory tasks breaks."""


class RegisteredTasks:
    """It is used to store registered tasks from plugin repositories."""

    def __init__(self):
        self.plugin_tasks = {}
        self.core_tasks = []

    def add_repo(self, repo_name, r_cfg):
        """Add repository information."""
        if repo_name not in self.plugin_tasks:
            self.plugin_tasks[repo_name] = copy.deepcopy(r_cfg)
            self.plugin_tasks[repo_name]['tasks'] = []

    def add_task(self, task, repo_name=None):
        """Add information about task from the repo with given name.
        If 'repo_name' is not defined the task will be added as a core tasks."""
        new_task = copy.deepcopy(task)

        if repo_name:
            self.plugin_tasks[repo_name]['tasks'].append(new_task)
        else:
            self.core_tasks.append(new_task)

    def get_all_tasks(self):
        """Get all tasks with information about the source.
        It can be the plugin repository or not defined if it is core task."""
        tasks = copy.deepcopy(self.core_tasks)

        for _, repository in self.plugin_tasks.items():
            for task in repository['tasks']:
                new_task = copy.deepcopy(task)
                new_task['source'] = repository['url']
                tasks.append(new_task)

        return tasks


class CachedTasksInfo:
    """It stores information about all tasks registered in Celery."""

    def __init__(self, cfg_store, cfg_gprn, registered_tasks):
        self.store = cfg_store
        self.cfg_gprn = cfg_gprn
        self.cache = get_cache(self.store)

        self.registered_tasks = registered_tasks

    def _get_plugin_key(self):
        """Get cache key for plugin tasks."""
        return self.store['key'] + ":plugin"

    def _get_tasks_key(self):
        """Get cache key for all registered tasks."""
        return self.store['key'] + ":tasks"

    def update(self):
        """It updates cache variable with registered tasks."""
        if self.cache:
            gprn = generate(
                {"environment": self.cfg_gprn.environment, "service": self.cfg_gprn.service})

            plugin_val = {
                "updated": str(datetime.now().astimezone()),
                "gprn": gprn,
                "repositories": self.registered_tasks.plugin_tasks
            }

            self.cache.set(
                self._get_plugin_key(),
                json.dumps(plugin_val),
                self.cache.cache_ttl)

            tasks_val = {
                "updated": str(datetime.now().astimezone()),
                "gprn": gprn,
                "tasks": self.registered_tasks.get_all_tasks()
            }

            self.cache.set(
                self._get_tasks_key(),
                json.dumps(tasks_val),
                self.cache.cache_ttl)

    def get_plugin_tasks(self):
        """Function gets all registered tasks. It gets them from cache."""
        return json.loads(self.cache.get(self._get_plugin_key()))

    def get_tasks(self):
        """Function gets all registered tasks. It gets them from cache."""
        return json.loads(self.cache.get(self._get_tasks_key()))


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
        self.registered_tasks = RegisteredTasks()

        cfg_store = self.cfg.celery.get("tasks_store")
        self.cached_tasks_info = None
        if cfg_store:
            cfg_gprn = self.cfg.gprn
            self.cached_tasks_info = CachedTasksInfo(cfg_store, cfg_gprn, self.registered_tasks)
        else:
            raise AttributeError("No `tasks_store` defined")

    def add_callable_info(self, callable_obj, options, task_def, repo_name=None):
        """Method adds info about callable to 'registered_tasks'."""
        task_name = options['name']
        keep_self = not options.get('bind', False)
        call_info = get_callable_info(callable_obj, keep_self)
        task = {"name": task_name}
        task.update(task_def)
        task.update({"callable_info": call_info})
        self.registered_tasks.add_task(task, repo_name)

    def register_config_tasks(self):
        """Method registers all task in Celery app, schedules them and prepares routes.
        The tasks definition is taken from configuration file."""
        self.register(self.tasks_def)

    def register(self, tasks_def, repo_cfg=None, path_to_tasks=""):
        """Register tasks."""
        for name in tasks_def:
            task_def = tasks_def[name]
            self._register_task_from_config(name, task_def, repo_cfg, path_to_tasks)

        self.schedule_tasks_from_config(tasks_def)
        self.prepare_routes(tasks_def)

    def _register_task_from_config(self, name, task_def, repo_cfg, path_to_tasks):
        callable_str = task_def["callable"]
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
                self.add_callable_info(func, opts, task_def)
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
        self, name, task, repo_url, repo_name, path_to_tasks, r_cfg
    ):
        """Function register one task from plugin."""
        if not task.get("enabled", True):
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
            callable_obj = get_plugin_callable(task, path_to_tasks)
            self.add_callable_info(callable_obj, opts, task, repo_name)
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
