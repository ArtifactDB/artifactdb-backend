import logging

from celery.schedules import crontab, timedelta

from artifactdb.utils.misc import get_callable_from_path


##################################
# TASKS REGISTATION & SCHEDULING #
##################################

class MandatoryTaskException(Exception):
    pass


def stop_if_mandatory(msg, mandatory):
    if mandatory:
        raise MandatoryTaskException(msg)
    logging.warning(msg)


def register_tasks_from_config(app, tasks_def):
    if not tasks_def:
        return app
    for name in tasks_def:
        mandatory = None
        try:
            mandatory = tasks_def[name].get("mandatory", False)
            callable_str = tasks_def[name]['callable']
            func, opts = get_callable_from_path(callable_str)
            app.task(func, **opts)
            logging.info(f"Registered task: '{name}'.")
        except ModuleNotFoundError:
            stop_if_mandatory(f"Module does not found when parsing the callable path: '{callable_str}'.", mandatory)
        except AttributeError:
            stop_if_mandatory(f"Function not found in module when parsing the callable path: '{callable_str}'.", mandatory)
        except Exception as e:  # pylint: disable=broad-except  # report anything else that failed during registration
            logging.exception(e)
            stop_if_mandatory(f"Error registering task '{name}': {e}", mandatory)

    return app


class TaskConfigException(Exception):
    pass


def prepare_task_routes(tasks_def, broadcast_queue_name, task_routes=None):
    task_routes = task_routes if task_routes else {}
    if not tasks_def:
        return task_routes
    if task_routes is None:
        task_routes = {}
    for name in tasks_def:
        if tasks_def[name].get('broadcast', False):
            task_routes[name] = {
                'queue': broadcast_queue_name,
                'exchange': broadcast_queue_name
            }

    return task_routes


def schedule_tasks_from_config(tasks_def, scheduler=None):
    scheduler = scheduler if scheduler else {}
    if not tasks_def:
        return scheduler
    for name in tasks_def:
        task = tasks_def[name]
        if not task.get('enabled', True):
            logging.info(f"Task: '{name}' is not enabled and it is not scheduled.")
            continue
        if not task.get('callable'):
            raise TaskConfigException(f"No definition for field: 'callable' for the task: '{name}'.")
        _, func = task['callable'].split('::')
        if name in scheduler:
            logging.warning("The key: {} exists in the celery scheduler. The key will be overriten.".format(name))
        if 'scheduler' in task.keys():
            if not task['scheduler'].get('type'):
                raise TaskConfigException(f"No definition for field: 'type' for the scheduler of task: '{name}'.")
            if not task['scheduler'].get('args'):
                raise TaskConfigException(f"No definition for field: 'args' for the scheduler of task: '{name}'.")
            scheduler_type = task['scheduler']['type']
            logging.info(f"Choosen scheduler: '{scheduler_type}' for task: '{name}'.")
            if scheduler_type == 'crontab':
                scheduler[name] = {}
                scheduler[name]['schedule'] = crontab(**task['scheduler'].get('args'))
                scheduler[name]['task'] = func
                logging.info(f"Scheduling task '{name}': '{scheduler[name]}'.")
            elif scheduler_type == 'timedelta':
                scheduler[name] = {}
                scheduler[name]['schedule'] = timedelta(**task['scheduler'].get('args'))
                scheduler[name]['task'] = func
                logging.info(f"Scheduling task '{name}': '{scheduler[name]}'.")
            elif scheduler_type == 'stages':
                logging.info(f"Staged task: '{name}' is scheduled by PluginsManager.")
            else:
                raise TaskConfigException(f"Unknown scheduler: '{scheduler_type}'. Task: '{name}' will not be scheduled.")

    return scheduler
