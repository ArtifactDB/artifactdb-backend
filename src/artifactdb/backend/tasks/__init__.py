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
