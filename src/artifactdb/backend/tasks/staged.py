import logging

class StagedTasks:

    def __init__(self, celery_app):
        self.staged_tasks = []
        self.celery_app = celery_app

    def reset(self):
        self.staged_tasks.clear()

    def has_project_id(self, task, project_id):
        return not task['project_ids'] or (project_id in task['project_ids'])


    def call_stage(self, stage, **kwargs):
        project_id = kwargs.get("project_id")
        logging.info(f"Stage called:{stage}")
        for task in self.staged_tasks:
            if self.has_stage(task, stage) and (not project_id or self.has_project_id(task, project_id)):
                self.call_task(task['name'], stage, **kwargs)


    def call_task(self, name, stage, **kwargs):
        kwargs["stage"] = stage
        self.celery_app.send_task(name, kwargs=kwargs)


    def schedule_staged_tasks(self, tasks_def):
        for name in tasks_def:
            self.schedule_task_if_staged(name, tasks_def[name])


    def schedule_task_if_staged(self, name, task):
        if self.has_stages(task):
            self.staged_tasks.append({
                "name": name,
                "stages": task['scheduler']['args'].get('stages', []),
                "project_ids": task['scheduler']['args'].get('project_ids', [])
            })


    def has_stage(self, task, stage):
        return not task['stages'] or (stage in task['stages'])


    def has_stages(self, task):
        return len(self.get_stages(task)) > 0


    def get_stages(self, task):
        if "scheduler" in task:
            return task['scheduler']['args'].get('stages', [])
        else:
            return []
