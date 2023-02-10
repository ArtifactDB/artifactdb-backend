import logging
from io import StringIO as StringBuffer

def task_params(**opts):
    """
    Decorator to catch params (opts) sent to app.task when
    app is available, along with the actual function.
    """
    def inner(func):
        # default settings for tasks options:
        if "private" not in opts:
            opts["private"] = False
        return func, opts
    return inner


def log_task(update_logs_func, task_name):
    """
    Decorator for saving logs in cache.
    Parameters:
        update_logs_func(task_name, log_content)  function which update log_content for task_name
        task_name task name
    """
    def inner(func):
        def new_func(*args, **kwargs):
            try:
                logging.info(f"Task logger called for: '{task_name}'.")

                logger = logging.getLogger()
                log_capture_string = StringBuffer()
                log_handler = logging.StreamHandler(log_capture_string)
                logger.addHandler(log_handler)
            except Exception as e: # pylint: disable=broad-except # do not stop if logs fails
                logging.exception(e)

            result = func(*args, **kwargs)

            try:
                log_content = log_capture_string.getvalue()
                logger.removeHandler(log_handler)
                log_capture_string.close()

                update_logs_func(task_name, log_content)
            except Exception as e: # pylint: disable=broad-except # do not stop if logs fails
                logging.exception(e)

            return result

        return new_func
    return inner
