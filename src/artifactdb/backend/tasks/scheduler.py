"""Module for creation scheduler for Celery application."""
import logging
from celery.schedules import crontab, timedelta


class SchedulerException(Exception):
    """Exception for scheduling process."""


class Scheduler:
    """Scheduler prepares the object for Celery scheduling."""

    def __init__(self, scheduler):
        self.scheduler = scheduler

    def get(self):
        """Get scheduler."""
        return self.scheduler

    def add_scheduler_def(self, name, celery_scheduler, func):
        """It adds scheduler definition to the final scheduler object."""
        self.scheduler[name] = {}
        self.scheduler[name]['schedule'] = celery_scheduler
        self.scheduler[name]['task'] = func
        logging.info(f"Scheduling task '{name}': '{self.scheduler[name]}'.")

    def choose_scheduler(self, name, task):
        """It chooses type of scheduler."""
        dummy, func = task['callable'].split('::')
        s_type = task['scheduler']['type']

        logging.info(f"Choosen scheduler: '{s_type}' for task: '{name}'.")
        if s_type == 'crontab':
            celery_scheduler = crontab(**task['scheduler'].get('args'))
            self.add_scheduler_def(name, celery_scheduler, func)
        elif s_type == 'timedelta':
            celery_scheduler = timedelta(**task['scheduler'].get('args'))
            self.add_scheduler_def(name, celery_scheduler, func)
        elif s_type == 'stages':
            logging.info(f"Staged task: '{name}' is scheduled by StagedTasks.")
        else:
            raise SchedulerException(
                f"Unknown scheduler: '{s_type}'. Task: '{name}' will not be scheduled.")

    def add_task(self, name, task):
        """Add task definition to scheduler."""
        if not task.get('enabled', True):
            logging.info(
                f"Task: '{name}' is not enabled and it is not scheduled.")
            return

        if not task.get('callable'):
            raise SchedulerException(
                f"No definition for field: 'callable' for the task: '{name}'.")

        if name in self.scheduler.keys():
            logging.warning(
                "The key: {} exists in the celery scheduler. The key will be overriten.".format(name))

        if 'scheduler' in task.keys():
            if not task['scheduler'].get('type'):
                raise SchedulerException(
                    f"No definition for field: 'type' for the scheduler of task: '{name}'.")

            if not task['scheduler'].get('args'):
                raise SchedulerException(
                    f"No definition for field: 'args' for the scheduler of task: '{name}'.")

            self.choose_scheduler(name, task)

    @staticmethod
    def schedule(celery_app, tasks_def):
        """The function set scheduler in Celery app based on given tasks definition."""
        scheduler = Scheduler(celery_app.conf.beat_schedule)

        if not tasks_def:
            return

        for name in tasks_def:
            task = tasks_def[name]
            scheduler.add_task(name, task)

        celery_app.conf.beat_schedule = scheduler.get()
