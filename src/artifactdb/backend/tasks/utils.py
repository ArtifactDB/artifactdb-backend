"""Plugin Utilities"""
import logging
import os

from artifactdb.backend.managers import RETRYABLE_EXCEPTIONS
from artifactdb.backend.components.queues import DEFAULT_TASK_PRIORITY
from artifactdb.backend.tasks.core import task_params
from artifactdb.utils.misc import compile_python_file

class PluginsRunException(Exception):
    """Exception for running plugin tasks."""

def is_plugin(task_def):
    """Function checks if defined tasks come from plugin repository. 
    Returns False if plugins are not defined in the ArtifactDB instance."""
    if "PLUGINS_PATH" not in os.environ:
        return False

    plugins_path = os.environ["PLUGINS_PATH"]
    return task_def['callable'].startswith(plugins_path)


def get_repo_for_task(repos_cfg, task_def):
    """It returns repositorory configuration for task definition. Returns None if task does not come from repository."""
    if is_plugin(task_def):
        callable_str = task_def['callable']
        repo_name = callable_str.split(".")[1]
        repo_cfg = filter(lambda r: r['name'] == repo_name, repos_cfg)
        return list(repo_cfg)[0]


def prepare_plugin_task(name, task, path_to_tasks, **gen_kwargs):
    """Function compile the action task in plugin and decorate it with @task_params.
    It returns the function abled to use as task in Celery app."""
    priority = task.get('priority', DEFAULT_TASK_PRIORITY)

    try:
        task_callable = get_plugin_callable(task, path_to_tasks)
        task_config_params = task.get('task_params', {})

        @task_params(bind=True, name=name, autoretry_for=RETRYABLE_EXCEPTIONS, default_retry_delay=30,
                     priority=priority, **task_config_params)
        def repo_task_func_staged(self_obj, **kwargs):
            try:
                gen_kwargs.update(kwargs)
                return task_callable(self_obj, **gen_kwargs)  # context
            except Exception as e: # pylint: disable=broad-except # catching all exceptions for called plugin task
                err_msg = f"Plugin task exception during call: {e}"
                logging.exception(err_msg)
                # The exception during the task run does not stop main instance of Celery.
                # Raising the exception here is necessary to show correct message in
                # job response - the result of PUT \task\run endpoint
                raise PluginsRunException(err_msg)

        return repo_task_func_staged

    except Exception as e: # pylint: disable=broad-except # catching all exceptions for called plugin task
        logging.exception(f"Plugin task exception during compilation: {e}")


def get_plugin_callable(task, path_to_tasks):
    """
    Function compiles task module and return callable.
    """
    file, str_callable = task['callable'].split("::")
    file = "/".join(file.split("."))

    if path_to_tasks:
        py_path = f"{path_to_tasks}/{file}.py"
    else:
        py_path = f"{file}.py"

    compiled = compile_python_file(py_path)
    return compiled[str_callable]
