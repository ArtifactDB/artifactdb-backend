from typing import Union
from aumbry import Attr
from .utils import PrintableYamlConfig


class TaskSchedulerConfig(PrintableYamlConfig):
    """
    Task scheduler configuration:
    - type: defines the scheduler type. One of:
      - timedelta: runs every X units, see celery.schedules.timedelta
      - crontab: cron notation, see celery.schedules.contrab
      - stages: runs when an project in an ArtifactDB instance reaches a certain stage. See adb.utils.stages
    - args: defines arguments for the scheduler type.
    """
    __mapping__ = {
        'type': Attr('type',str),  # "timedelta", "crontab", "stages"
        'args': Attr('args',dict),
    }


class TaskConfig(PrintableYamlConfig):
    """
    Defines a task:
    - mandatory: makes sure the tasks can properly be created, and will fail if not (otherwise, ignored)
    - broadcast: ensures the tasks is registered in all workers (for scheduler supporting that)
    - callable: string representing the function to call when the task is executed.
                Format: one.module::function_name
    - params: sets of parameters passed to the callable
    - scheduler: defines if and how the tasks is scheduled.
    """
    __mapping__ = {
        'mandatory': Attr('mandatory', bool),
        'broadcast': Attr('broadcast', bool),
        'callable': Attr('callable', str),
        'params': Attr('params',dict),
        'scheduler': Attr('scheduler', TaskSchedulerConfig),
    }

    mandatory = False
    broadcast = False
    params = {}
    scheduler = None

