import logging

from fastapi.requests import Request
from fastapi.responses import JSONResponse


class SwitchMiddlewareBase:
    """
    Generic switch middleware which, given a switch config and
    context vars, performs sanity checks and set the context vars
    accordingly.
    """

    def __init__(self, switch_cfg, data_ctx_var, switch_ctx_var):
        """
        `switch_cfg` is a artifactdb.config.switches.Switch instance
        `data_ctx_var` is the context var holding the data behind the switch value.
        `switch_ctx_var` is the switch value found from the header specified in the config
        (eg. "v1", "v2", ...)
        """
        self.switch_cfg = switch_cfg
        self.header = self.switch_cfg.header
        self.contexts = self.switch_cfg.contexts
        self.data_ctx_var = data_ctx_var
        self.switch_ctx_var = switch_ctx_var
        assert self.header
        assert self.contexts

    async def set_switch_context(self, request: Request, call_next):

        assert self.data_ctx_var.get() is None
        data_ctx = None
        switch_ctx = None
        data = None
        switch_value = None

        if self.header in request.headers:
            switch_value = request.headers[self.header]
            if not switch_value in self.contexts:
                return JSONResponse(
                    status_code=400,
                    content={
                        "detail": f"Invalid value for header {self.header}. " + \
                                  "Allowed: {}".format(list(self.contexts.keys())),
                    }
                )
            data = self.contexts[switch_value]
            data_ctx = self.data_ctx_var.set(data)
            switch_ctx = self.switch_ctx_var.set(switch_value)

        if not request.url.path in ("/","/status","/index/status"):
            logging.info(f"Setting context var {self.data_ctx_var}, switch_value: {switch_value}, data: {data}")

        response = await call_next(request)

        if data_ctx:
            self.data_ctx_var.reset(data_ctx)
            self.switch_ctx_var.reset(switch_ctx)

        return response


