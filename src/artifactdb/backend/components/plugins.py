"""Functionality for registering tasks from plugins."""
import os
import logging
import glob
import yaml

from artifactdb.backend.tasks import task_params
from artifactdb.backend.tasks.core import ask_for_restart
from artifactdb.backend.managers import RETRYABLE_EXCEPTIONS
from artifactdb.utils.misc import add_sys_path
from artifactdb.backend.git import GitManager
from artifactdb.backend.components import BackendComponent, InvalidComponentError

class PluginsConfigException(Exception): pass
class PluginsException(Exception): pass

class PluginsManager(BackendComponent):
    """Plugin manager is a class used for registering tasks from plugin repositories."""

    NAME = "plugins"
    FEATURES = ["plugins",]
    DEPENDS_ON = ["tasks",]

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
        self.task_mgr = manager.tasks
        self.cfg = cfg
        self.git_mgr = GitManager()

    def register_repository_tasks_safe(self, pull):
        """It register all task repositories.
        Logging all exception without breaking the execution."""
        try:
            self.stop_if_plugins_path_not_exists()
            self.register_repository_tasks(pull)
        except PluginsConfigException as err:
            logging.warning(
                f"Unable to register plugins, configuration issue: {err}")
        except Exception as err: # pylint: disable=broad-except # catching all exceptions for registration of plugin task
            logging.exception(f"Exception while registering plugin: {err}")

    def stop_if_plugins_path_not_exists(self):
        """It throws exception if 'PLUGINS_PATH' environment variable is not defined."""
        plugins_path = os.environ.get("PLUGINS_PATH")
        if not plugins_path:
            raise PluginsConfigException(
                "Environment variable: 'PLUGINS_PATH' not defined.")

    def register_repository_tasks(self, pull):
        """It register all task repositories."""
        repos_cfg = self.cfg.celery.get('repo')
        if repos_cfg:
            self.register_tasks_from_repos(repos_cfg, pull)

    def register_tasks_from_repos(self, repos_cfg, pull):
        """It register all tasks for all plugin repositories."""
        for r_cfg in repos_cfg:
            self.register_tasks_from_one_repo(r_cfg, pull)

    def register_tasks_from_one_repo(self, r_cfg, pull):
        """It register all tasks for the repository."""
        repo_dir = self.git_mgr.get_plugin_repo(r_cfg, pull)
        task_dir = r_cfg.get('folder', "")
        add_sys_path(repo_dir)

        manifest_tab = self.read_all_manifests(repo_dir, task_dir)

        for manifest in manifest_tab:
            tasks_def = manifest.get('tasks', None)
            manifest_dir = manifest['directory']
            self.register_tasks_for_manifest(tasks_def, manifest_dir, r_cfg)

    def register_tasks_for_manifest(self, tasks_def, manifest_dir, r_cfg):
        """It register task for one manifest file."""
        add_sys_path(manifest_dir)

        self.task_mgr.register(tasks_def, repo_cfg=r_cfg, path_to_tasks=manifest_dir)

    def read_all_manifests(self, repo_dir, task_dir):
        """It reads all manifest files for the given repository.
        It returns list of dictionary."""
        search_path = f"{repo_dir}/{task_dir}"
        manifest_paths = glob.glob(
            f"{search_path}/**/manifest.yaml",
            recursive=True)
        return list(map(self.read_manifest, manifest_paths))

    def read_manifest(self, manifest_path):
        """It reads manifest file for tasks. It returns dictionary."""
        with open(manifest_path, 'r') as stream:
            manifest = yaml.safe_load(stream)
            manifest['directory'] = os.path.dirname(manifest_path)
            return manifest


#########
# TASKS #
#########

@task_params(bind=True,
             name="pull_plugin_repos",
             autoretry_for=RETRYABLE_EXCEPTIONS,
             default_retry_delay=30,
             ignore_result=True)
def pull_plugin_repos(self):
    """The broadcasted task function for pulling plugin repositories."""
    if not self._app.manager.plugins:
        logging.info("Plugins not configured. Nothing to pull.")
        return

    git_mgr = GitManager()
    cfg = self._app.manager.cfg
    repos_cfg = cfg.celery.get('repo')

    if repos_cfg:
        fetch_tab = git_mgr.pull_repos(repos_cfg)

        if git_mgr.is_any_repo_updated(fetch_tab):
            ask_for_restart(self)
