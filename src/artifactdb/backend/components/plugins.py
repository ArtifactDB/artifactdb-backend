# pylint: disable=unpacking-non-sequence
import os
import logging
import glob
import json
from datetime import datetime

import yaml

from gpapy.backend.tasks import task_params
from gpapy.backend.tasks import ask_for_restart
from gpapy.backend.scheduler import schedule_tasks_from_config
from gpapy.backend.manager_exceptions import RETRYABLE_EXCEPTIONS
from gpapy.db.schema import get_cache
from gpapy.backend.queues import DEFAULT_TASK_PRIORITY

from artifactdb.backend.components import BackendComponent, InvalidComponentError
from artifactdb.identifiers.gprn import generate
from artifactdb.utils.misc import add_sys_path
from artifactdb.backend.git import GitManager

class PluginsConfigException(Exception): pass
class PluginsException(Exception): pass


class PluginsManager(BackendComponent):

    NAME = "plugins"
    FEATURES = ["plugins","staged-tasks",]
    DEPENDS_ON = []

    def __init__(self, manager, cfg):
        self.cfg = cfg
        # first sanity checks, raising InvalidComponentError is anything wrong,
        # per artifactdb.backend.BackendComponent ABC class.
        store = self.cfg.celery.get("tasks_store")
        plugins_path = os.environ.get("PLUGINS_PATH")
        if not store:
            raise InvalidComponentError("Can't use plugins without `celery.tasks_store` defined in configuration")
        if not plugins_path:
            raise InvalidComponentError("Can't use plugins without env. variable `PLUGINS_PATH` set")
        self.celery_app = manager.celery_app
        self.git_manager = GitManager()
        self.staged_tasks = []
        self.reg_tasks = {}
        store = self.cfg.celery["tasks_store"] # make the cache obligatory
        self.cache = get_cache(store)

    def update_tasks(self):
        if self.cache:
            gprn = generate({"environment": self.cfg.gprn.environment, "service": self.cfg.gprn.service})
            new_val = {
                "updated": str(datetime.now().astimezone()),
                "gprn": gprn,
                "repositories": self.reg_tasks
            }
            store = self.cfg.celery["tasks_store"]
            self.cache.set(store['key'], json.dumps(new_val), self.cache.cache_ttl)

    def get_tasks(self):
        store = self.cfg.celery["tasks_store"]
        return json.loads(self.cache.get(store['key']))

    def call_stage(self, stage, project_id, version=None):
        logging.info(f"Stage called:{stage}")
        for task in self.staged_tasks:
            if self.has_stage(task, stage) and self.has_project_id(task, project_id):
                self.call_task(task['name'], stage, project_id, version)

    def has_stage(self, task, stage):
        return not task['stages'] or (stage in task['stages'])

    def has_project_id(self, task, project_id):
        return not task['project_ids'] or (project_id in task['project_ids'])

    def call_task(self, name, stage, project_id, version):
        kwargs = {
            "stage": stage,
            "project_id": project_id,
            "version": version
        }
        self.celery_app.send_task(name, kwargs=kwargs)

    def register_repository_tasks_safe(self, pull):
        try:
            self.stop_if_plugins_path_not_exists()
            self.register_repository_tasks(pull)
        except PluginsConfigException as exc:
            logging.warning(f"Unable to register plugins, configuration issue: {exc}")
        except Exception as exc:  # pylint: disable=broad-except  # we need to know what is wrong there
            logging.exception(f"Exception while registering plugin: {exc}")

    def stop_if_plugins_path_not_exists(self):
        plugins_path = os.environ.get("PLUGINS_PATH")
        if not plugins_path:
            raise PluginsConfigException("Environment variable: 'PLUGINS_PATH' not defined.")

    def stop_if_plugins_settings_wrong(self):
        plugins_path = os.environ.get("PLUGINS_PATH")
        if not plugins_path:
            raise PluginsConfigException("Environment variable: 'PLUGINS_PATH' not defined.")

    def register_repository_tasks(self, pull):
        repos_cfg = self.cfg.celery.get('repo')
        if repos_cfg:
            self.register_tasks_from_repos(repos_cfg, pull)

    def register_tasks_from_repos(self, repos_cfg, pull):
        for r_cfg in repos_cfg:
            self.register_tasks_from_one_repo(r_cfg, pull)

    def register_tasks_from_one_repo(self, r_cfg, pull):
        repo_dir = self.git_manager.get_plugin_repo(r_cfg, pull)
        task_dir = r_cfg.get('folder', "")
        repo_name = r_cfg['name']
        add_sys_path(repo_dir)
        manifest_tab = self.read_all_manifests(repo_dir, task_dir)
        self.reg_tasks[repo_name] = r_cfg
        self.reg_tasks[repo_name]['tasks'] = []
        for manifest in manifest_tab:
            self.register_tasks_for_manifest(manifest, r_cfg)

    def register_tasks_for_manifest(self, manifest, r_cfg):
        repo_url = r_cfg['url']
        repo_name = r_cfg['name']
        tasks_def = manifest.get('tasks', None)
        path_to_tasks = manifest['directory']
        add_sys_path(path_to_tasks)
        if tasks_def:
            for name in tasks_def:
                task = tasks_def[name]
                if not task.get('enabled', True):
                    logging.info(f"Task: '{name}' is not enabled, skipped")
                    continue # task not enabled
                task_name = self._get_task_name(task)
                is_staged = self.has_stages(task)
                if not is_staged:
                    func,opts = self.prepare_dynamic_repo_task(task,path_to_tasks)
                else:
                    func,opts = self.prepare_dynamic_repo_staged_task(task,path_to_tasks,repo_cfg=r_cfg)
                if not task_name in self.celery_app.tasks:
                    self.celery_app.task(func, **opts)
                    self.reg_tasks[repo_name]['tasks'].append(task)
                    logging.info(f"Registered task: '{name}' from repo: {repo_url}.")
                else:
                    logging.info(
                        f"Task: '{name}'. The name: '{task_name}' belongs to task previously registered in celery app.")
                if is_staged:
                    self.staged_tasks.append({
                        "name": name,
                        "stages": task['scheduler']['args'].get('stages', []),
                        "project_ids": task['scheduler']['args'].get('project_ids', [])
                    })
        self.celery_app.conf.beat_schedule = schedule_tasks_from_config(tasks_def, scheduler = self.celery_app.conf.beat_schedule)

    def read_all_manifests(self, repo_dir, task_dir):
        search_path = f"{repo_dir}/{task_dir}"
        manifest_paths = glob.glob(f"{search_path}/**/manifest.yaml", recursive=True)
        return list(map(self.read_manifest, manifest_paths))

    def read_manifest(self, manifest_path):
        with open(manifest_path, 'r') as stream:
            manifest = yaml.safe_load(stream)
            manifest['directory'] = os.path.dirname(manifest_path)
            return manifest

    def _get_task_name(self, task):
        _,str_callable = task['callable'].split("::")
        return str_callable

    def has_stages(self, task):
        return len(self.get_stages(task)) > 0

    def get_stages(self, task):
        return task['scheduler']['args'].get('stages', [])

    def prepare_dynamic_repo_task(self, task, path_to_tasks):
        fname, str_callable = task['callable'].split("::")
        priority = task.get('priority', DEFAULT_TASK_PRIORITY)

        @task_params(bind=True, name=str_callable, autoretry_for=RETRYABLE_EXCEPTIONS, default_retry_delay=30, priority=priority)
        def repo_task_func(self_obj):
            py_path = f"{path_to_tasks}/{fname}.py"
            try:
                nsp = self.compile_ns(py_path)
                return nsp[str_callable](self_obj) # context
            except Exception as exc:  # pylint: disable=broad-except  # we need to know what is wrong there
                logging.exception(f"Exception from registering plugin: {exc}")

        return repo_task_func

    def prepare_dynamic_repo_staged_task(self, task, path_to_tasks, repo_cfg):
        fname, str_callable = task['callable'].split("::")
        priority = task.get('priority', DEFAULT_TASK_PRIORITY)

        @task_params(bind=True, name=str_callable, autoretry_for=RETRYABLE_EXCEPTIONS, default_retry_delay=30, priority=priority)
        def repo_task_func(self_obj, stage, project_id, version):
            py_path = f"{path_to_tasks}/{fname}.py"
            try:
                nsp = self.compile_ns(py_path)
                return nsp[str_callable](self_obj, stage, project_id, version, repo_cfg)
            except Exception as exc:  # pylint: disable=broad-except  # we need to know what is wrong there
                logging.exception(f"Exception from registering plugin: {exc}")

        return repo_task_func

    def compile_ns(self, py_path):
        nsp = {}
        with open(py_path) as fin:
            code = compile(fin.read(), py_path, 'exec')
            exec(code, nsp, nsp)  # pylint: disable=exec-used  # until we have sandboxed env...

            return nsp


#########
# TASKS #
#########

@task_params(bind=True, name="pull_plugin_repos", autoretry_for=RETRYABLE_EXCEPTIONS, default_retry_delay=30, ignore_result = True)
def pull_plugin_repos(self):
    if not self._app.manager.plugins:
        logging.info("Plugins not configured. Nothing to pull.")
        return
    try:
        git_mgr = GitManager()
        cfg = self._app.manager.cfg
        repos_cfg = cfg.celery.get('repo')
        if repos_cfg:
            fetch_tab = git_mgr.pull_repos(repos_cfg)
            if git_mgr.is_any_repo_updated(fetch_tab):
                ask_for_restart(self)
    except Exception as exc:  # pylint: disable=broad-except  # we need to know what is wrong there
        logging.exception(f"Exception from the 'pull_plugin_repos' task: {exc}")

