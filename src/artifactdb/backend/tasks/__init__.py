def task_params(**opts):
    """
    Decorator to catch params (opts) sent to app.task when
    app is available, along with the actual function.
    """
    def inner(func):
        return func, opts
    return inner


