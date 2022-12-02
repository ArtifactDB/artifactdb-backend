# pylint: disable=unused-argument  # `request`, to respect fastapi hooks signature
import os
import logging

from fastapi import FastAPI, HTTPException, Request, APIRouter
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.openapi.utils import get_openapi
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html, get_swagger_ui_oauth2_redirect_html

from artifactdb.db.elastic.manager import NotAllowedException
from artifactdb.rest.resources import APIErrorException, PrettyJSONResponse
from artifactdb.rest.middleware.authcontext import AuthContextMiddleware
from artifactdb.rest.middleware.es_switch import ESSwitchMiddleware
from artifactdb.rest.middleware.storage_switch import StorageSwitchMiddleware
# Usual resources
from artifactdb.rest.resources import info
from artifactdb.rest.resources import tasks
from artifactdb.rest.resources import status
from artifactdb.rest.resources import config
from artifactdb.rest.resources import schemas
from artifactdb.rest.resources import jobs
from artifactdb.rest.resources import index
from artifactdb.rest.resources import projects
from artifactdb.rest.resources import permissions
from artifactdb.rest.resources import files
from artifactdb.rest.resources import search
from artifactdb.rest.resources import sequences
from artifactdb.rest.resources import upload
from artifactdb.rest.resources import gprn
from artifactdb.rest.resources import maintenance


class BaseRESTAPI(FastAPI):

    RESOURCES = {}  # must be defined in a sub-class depending on the type of REST API

    def __init__(self, title, cfg, dependency_manager, custom_resources=None):
        self.title = title
        self.cfg = cfg
        self.dependency_manager = dependency_manager
        self.dependency_manager.app = self
        super().__init__(title=self.title,
                         docs_url=None, redoc_url=None,
                         default_response_class=PrettyJSONResponse)
        self.setup_exception_handlers()
        self.setup_openapi()
        self.setup_swagger()
        resources = custom_resources or self.__class__.RESOURCES
        self.register_resources(resources)
        self.register_middlewares()
        self.enable_auth()  # after previous middleware, so auth is done first

    def register_resources(self, resources):
        for _,resource_def in resources.items():
            logging.info("Registering resource {}".format(resource_def))
            # either direct a class defining the resource, or a dict.
            # let's normalize
            if isinstance(resource_def,type):
                resource_def = {"class": resource_def}
            resource = resource_def["class"]
            pred = resource_def.get("predicate")
            if pred and not pred(self):
                logging.info(f"Not registering {resource} because predicate said so")
                continue
            resource.router = APIRouter()
            resource.deps = self.dependency_manager
            resource.activate_routes()
            self.merge(resource)
            self.include_router(resource.router)

    def merge(self, resource):
        """
        Merge resource's routes into existing ones, superseding them
        while propagating the original/superseded API route to new
        resource handler.
        If no existing path are found, the merge does nothing.
        """
        existing_routes = [r.path for r in self.routes]
        for route in resource.router.routes:
            if route.path in existing_routes:
                idx = existing_routes.index(route.path)
                logging.info("Superseding route {} using resource {}".format(route.path,resource))
                resource.PARENT_HANDLER = self.routes[idx]  # in case superseder wants to use original handler
                self.routes.pop(idx)

    def register_middlewares(self):
        """
        Placeholder to register custom middleware.
        """

    def enable_auth(self, auth_middleware_class=AuthContextMiddleware):
        # Middleware to set a context var for api user
        # so all components in the API can access it for given
        # request
        authr = self.dependency_manager.get_authorizer()
        self.auth_ctx_middleware = auth_middleware_class(auth_conf=self.cfg.auth,authorizer=authr)
        self.middleware("http")(self.auth_ctx_middleware.set_auth_user_context)

    def setup_exception_handlers(self):
        @self.exception_handler(APIErrorException)
        async def unicorn_exception_handler(request: Request, exc: APIErrorException):
            return JSONResponse(status_code=exc.status_code,
                    content={"status": exc.status, "reason": exc.reason}
            )

        @self.exception_handler(NotAllowedException)
        async def unicorn_not_allowed_exception_handler(request: Request, exc: NotAllowedException):
            return JSONResponse(status_code=403,content={"status": "forbidden", "reason": str(exc)})

        @self.exception_handler(HTTPException)
        async def normalize_error_message_field(request: Request, exc: HTTPException):
            # see ADB-44
            return JSONResponse(status_code=exc.status_code,content={"status": "error", "reason": exc.detail})

    def setup_openapi(self):

        def custom_openapi(openapi_prefix: str):
            if self.openapi_schema:
                return self.openapi_schema
            openapi_schema = get_openapi(
                title=self.title,
                version="version={},env={},build={}".format(self.cfg.version,self.cfg.env,self.cfg.build),
                description='<img src="{}" width="30%">'.format(self.cfg.logo_url),
                routes=self.routes,
                openapi_prefix=openapi_prefix,
                servers = [{"url":prefix} for prefix in self.cfg.prefixes],
            )
            openapi_schema["info"]["x-logo"] = {
                "url": "https://fastapi.tiangolo.com/img/logo-margin/logo-teal.png"
            }
            self.openapi_schema = openapi_schema
            return self.openapi_schema

        self.openapi = custom_openapi

    def setup_swagger(self):
        self.mount("/static", StaticFiles(directory="static"), name="static")
        # we assume the first prefix is the one that will allow the redirection
        redir_prefix = self.cfg.prefixes[0]
        redir_url = "/{}".format(os.path.join(redir_prefix.strip("/"),self.swagger_ui_oauth2_redirect_url.strip("/")))
        logging.debug(f"OAuth2 redirection URL: {redir_url}")

        @self.get("/__swagger__", include_in_schema=False)
        async def custom_swagger_ui_html():
            return get_swagger_ui_html(
                # remove "/" from url so it's relative and proxy-friendly
                openapi_url=self.openapi_url.lstrip("/"),
                title=self.title + " - Swagger UI",
                oauth2_redirect_url=redir_url,
                swagger_js_url="static/swagger-ui-bundle.js",
                swagger_css_url="static/swagger-ui.css",
                swagger_favicon_url= "static/favicon.ico",
                init_oauth= {
                    "clientId": self.cfg.auth.oidc.client_id,
                    "appName": self.cfg.auth.app_name,
                    "clientSecret": "notneeded",
                }
            )

        # the redirection URL contains the prefix is any, but when keycloak goes back and
        # reach the API, we need to react on the path without the prefix because the prefix is removed
        # by the ingress proxy by default. (yes, this is not clean...)
        @self.get(self.swagger_ui_oauth2_redirect_url, include_in_schema=False)
        async def swagger_ui_redirect():
            redir = get_swagger_ui_oauth2_redirect_html()
            return redir


class ArtifactDBApi(BaseRESTAPI):

    # standard/usual API endpoints for an ArtifactDB API
    RESOURCES = {
        "projects": projects.ProjectsResource,
        "search": search.SearchResource,
        "files": files.FilesResource,
        "permissions": permissions.PermissionsResource,
        "info": info.InfoResource,
        "tasks": tasks.TasksResource,
        "status": status.StatusResource,
        "index": index.IndexResource,
        "config": config.ConfigResource,
        "schemas": schemas.SchemasResource,
        "jobs": jobs.JobsResource,
        "upload": upload.UploadResource,
        "gprn": gprn.GPRNResource,
        "maintenance": maintenance.MaintenanceResource,
        # conditional resource declaration
        "sequence": {
            "class": sequences.SequencesResource,
            "predicate": lambda self: self.dependency_manager.get_sequence_manager(),
        },
    }

    def register_middlewares(self):
        super().register_middlewares()
        # switcher for elasticsearch indices
        if hasattr(self.cfg,"es") and hasattr(self.cfg.es,"switch") and self.cfg.es.switch.header:
            logging.info(f"Registering 'es_switch' middleware, rules: {self.cfg.es.switch}")
            self.es_switch_middleware = ESSwitchMiddleware(self.cfg.es.switch)
            self.middleware("http")(self.es_switch_middleware.set_switch_context)
        else:
            logging.info("No 'es_switch' middleware declaration in config, skip")

        # switcher for storage clients
        if hasattr(self.cfg,"storage") and hasattr(self.cfg.storage,"switch") and self.cfg.storage.switch.header:
            logging.info(f"Registering 'storage_switch' middleware, rules: {self.cfg.storage.switch}")
            self.storage_switch_middleware = StorageSwitchMiddleware(self.cfg.storage.switch)
            self.middleware("http")(self.storage_switch_middleware.set_switch_context)
        else:
            logging.info("No 'storage_switch' middleware declaration in config, skip")

        # CORS
        if hasattr(self.cfg,"cors") and self.cfg.cors.enabled:
            logging.info("Enabled CORS: {}".format(self.cfg.cors.to_dict()))
            self.add_middleware(
                CORSMiddleware,
                allow_origins=self.cfg.cors.allow_origins,
                allow_methods=self.cfg.cors.allow_methods,
                allow_headers=self.cfg.cors.allow_headers,
            )


