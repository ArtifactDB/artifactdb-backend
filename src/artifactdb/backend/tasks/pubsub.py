import logging

from artifactdb.backend.components.locks import RE_INDEXING
from artifactdb.backend.tasks import task_params
from artifactdb.backend.managers import RETRYABLE_EXCEPTIONS
from artifactdb.utils.stages import INDEXED, FAILED, ALL_INDEXED, ALL_INDEXED_FAILED


@task_params(bind=True,name="publish_all_indexed",autoretry_for=RETRYABLE_EXCEPTIONS,default_retry_delay=30)
def publish_all_indexed(self, projects):
    """
    This tasks is triggered by the index_all tasks, as the chord's callback.
    Signature is special, it takes the output of all indexing tasks, so
    it has to be a dedicated task to prepare the publishing.
    """
    # release re-indexing lock
    self._app.manager.lock_manager.release(RE_INDEXING,force=True)
    msg = "Fully redindexed {} project(s): {}".format(len(projects),projects)
    kw = {
        "project_id": None,
        "message": {
            "message": msg,
            "project_id": None,
            "version": None
        },
        "stage": INDEXED,
        "use_schema": False
    }
    logging.info(msg)
    self._app.send_task("publish_event",kwargs=kw)

    self._app.manager.tasks.staged_tasks.call_stage(stage=ALL_INDEXED)


@task_params(bind=True,name="publish_all_indexed_failed",autoretry_for=RETRYABLE_EXCEPTIONS,default_retry_delay=30)
def publish_all_indexed_failed(self, task_id, *args, **kwargs):  # pylint: disable=unused-argument  # celery puts some more we don't care about
    """
    This tasks is triggered by the index_all tasks, as the chord's callback.
    """
    # release re-indexing lock
    self._app.manager.lock_manager.release(RE_INDEXING,force=True)
    msg = "Redindexing error {}".format(task_id)
    kw = {
        "project_id": None,
        "message": {
            "message": msg,
            "project_id": None,
            "version": None
        },
        "stage": FAILED,
        "use_schema": False
    }
    logging.info(msg)
    self._app.send_task("publish_event",kwargs=kw)

    self._app.manager.tasks.staged_tasks.call_stage(stage=ALL_INDEXED_FAILED)
