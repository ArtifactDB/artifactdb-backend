import logging
import datetime
from typing import List

from fastapi import Depends, Query, Request
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field
from elasticsearch.exceptions import RequestError

from artifactdb.utils.jsonpatch import InvalidJsonPatch
from artifactdb.db.elastic.client import ForbiddenOperation, MappingUpdateError
from artifactdb.db.elastic.manager import IndexNamingConventionError
from artifactdb.db.elastic import NotFoundError
from artifactdb.identifiers.gprn import generate as generate_gprn, parse as parse_gprn
from artifactdb.backend.components.locks import ProjectLockedError, RE_INDEXING
from artifactdb.rest.helpers import get_job_response
from artifactdb.rest.resources import APIErrorException, APIError, SubmittedJob, NotAuthenticated, \
                                      Forbidden, ResourceBase


class ProjectIds(BaseModel):
    project_ids: List[str] = Field(...,description="JSON list or project IDs to index (or all if ommitted)")
    class Config:
        schema_extra = {
            "example": {
                "project_ids" : ["ID1","ID2","ID6"],
            }
        }


class MappingDiffs(BaseModel):
    """
    Diff operations directly applied to an Elastic mapping. Diffs are usually automatically generated
    by diffings the models themselves. The diffs operation listed there are applied to the mapping itself,
    if the field(s) part of that update is not part of the model, this will result in a model/mapping desync:
    - a new field was added to the mapping
    - that field is not declared in the model
    - /index/status endpoint will a `remove` operation is required to bring the model to the mapping state.
    In order to prevent this situation, the diffs listed here must match one the diff operations found diffing
    models. In other word, only a subset of all the diffs found diffings models can be applied... except if
    force=true, in which case, no question asked, diff ops are applied  (highly *NOT* recommended)
    """
    diffs:List[dict] = Field(...,description="List of JSON diff/patch operations")
    force:bool = Field(False,description="Apply diff operations regardless of current model diffs status")
    class Config:
        schema_extra = {
            "example": {
                "diffs" : [{"op": "add", "path": "/properties/newfield", "value": {"type": "keyword"}}],
            }
        }


def verify_subset_diffs(all_diffs, diffs):
    """
    `all_diffs` represents all diffs found when client.check(), that is, current
    diffs representing the desync between model and mappings. `diffs` is a set of
    explicit diff operations. This function verifies `diffs` contains operations found
    in `all_diffs` (ie. is a subset)
    """
    all_diffs = all_diffs or []
    for diff in diffs:
        if not diff in all_diffs:
            raise ForbiddenOperation(diff)


class IndexResource(ResourceBase):

    @classmethod
    def activate_routes(cls):


        #####################
        # BATCH RE-INDEXING #
        #####################

        @cls.router.put("/index/build",
                description="Create an index based on all entries in the S3 bucket",
                response_description="indexing job was accepted and will be processed as soon as possible",
                responses={
                    404:{"model":APIError},
                    202:{"model":SubmittedJob},
                    401:{"model":NotAuthenticated},
                    403:{"model":Forbidden},
                    },
                tags=["admin"],
                status_code=202)
        def index_all(
            request:Request,
            project_ids: ProjectIds = None,
            storage_alias:str = Query(None,description="Storage alias (or default one if not specified) " + \
                                      "from which metadata is pulled and indexed"),
            celery_app = Depends(cls.deps.get_celery_app),
            lock_manager=Depends(cls.deps.get_lock_manager),
            _:str = Depends(cls.deps.get_authorizer(roles=["admin"],access_rules=[])),
        ):
            project_ids = jsonable_encoder(project_ids)
            # either a json list was passed, or a comma-sep string
            if isinstance(project_ids,str):
                project_ids = list(map(str.strip,project_ids.split(",")))

            try:
                info = {
                    "total": project_ids and len(project_ids),
                    "storage_alias": storage_alias,
                }
                lock_manager.lock(RE_INDEXING,stage="index_all",info=info)
                res = celery_app.send_task("index_all",
                        kwargs=dict(
                            project_ids=project_ids,
                            storage_alias=storage_alias,
                      ))
                resp = get_job_response(res.id,request)

            except ProjectLockedError as e:
                msg = "Re-indexing already in progress"
                logging.warning(f"{msg}: {e}")
                lock_info = None
                try:
                    # enrich error with some lock information
                    lock_info = lock_manager.info(RE_INDEXING)
                except Exception as exc:  # pylint: disable=broad-except  # TODO: should not be that broad
                    logging.error("Can't fetch lock info: {}".format(exc))
                    lock_info = "(no lock information)"
                raise APIErrorException(
                    status_code=423,
                    status="error",
                    reason=f"{msg}: {lock_info}"
                )

            return resp


        #######################
        # GLOBAL INDEX STATUS #
        #######################

        @cls.router.get("/index/status",
                description="Report status about index, alias, and models",
                tags=["admin"],
                status_code=200)
        def status(
                celery_app = Depends(cls.deps.get_celery_app),
            ):
            mgr = celery_app.manager
            aliases = mgr.es_aliases()
            aliases_synced = mgr.es_aliases_synced()
            models_diffs = mgr.es.check_models()
            # if any diffs in the models, we're not in sync
            # - [] means no diff, all good
            # - None means there's no model! not good
            # - [...] contains a diff ops, not good
            if {True for _ in models_diffs.values() if _ != []}:
                models_synced = False
            else:
                models_synced = True
            resp = {
                "aliases": {},
                "config" : {
                    "backend": mgr.cfg.es.backend.to_dict(),
                    "frontend": mgr.cfg.es.frontend.to_dict(),
                },
                "models": {
                    "diffs": models_diffs,
                    "synced": models_synced,
                },
            }
            if aliases:
                resp["aliases"] = {
                    "synced": aliases_synced,
                    "clients": aliases,
                }

            return resp

        @cls.router.get("/index/settings",
                description="List indices, active and inactive (old) ones",
                tags=["admin"],
                status_code=200)
        def index_settings(
                celery_app = Depends(cls.deps.get_celery_app),
                _:str = Depends(cls.deps.get_authorizer(roles=["admin"],access_rules=[])),
            ):
            try:
                return celery_app.manager.es.list_indices()
            except IndexNamingConventionError as e:
                logging.exception(e)
                raise APIErrorException(500,status="error",reason=f"Inconsistency found in configuration: {e}")

        @cls.router.delete("/index/{alias}/inactive",
                description="Delete inactive indices for given Elastic client `alias`, oldest first",
                tags=["admin"],
                status_code=200)
        def clean_inactive_indices(
                alias:str = Query(...,description="Client alias to delete the indices from"),
                keep:int = Query(5,description="Only keep this number of old/inactive indices",ge=0),
                celery_app = Depends(cls.deps.get_celery_app),
                _:str = Depends(cls.deps.get_authorizer(roles=["admin"],access_rules=[])),
            ):
            try:
                deleted = celery_app.manager.es.clean_inactive_indices(alias,keep=keep)
                return {"deleted": deleted}
            except KeyError as e:
                raise APIErrorException(404,status="error",reason=f"Unknown alias {alias!r}: {e}")
            except NotFoundError as e:
                raise APIErrorException(404,status="error",reason=f"Unable to delete inactive index: {e}")
            except IndexNamingConventionError as e:
                raise APIErrorException(500,status="error",reason=f"Inconsistency found in configuration: {e}")


        ##########
        # MODELS #
        ##########

        @cls.router.put("/index/models/generate",
                description="Generate models registered as `dynamic` in the configuration file. For models " + \
                            "from schemas, cached schemas may be used. To force using most up-to-data schemas, " + \
                            "the schema cache should first be cleared",
                responses={
                    404:{"model":APIError},
                    401:{"model":NotAuthenticated},
                    403:{"model":Forbidden},
                    },
                tags=["admin"],
                status_code=200)
        def generate_models(
                request:Request,
                client:str = Query(None,description="Client alias to generate model for (all clients by default)"),
                preview:bool = Query(False,description="Don't activate the models but store it as a preview model"),
                celery_app = Depends(cls.deps.get_celery_app),
                _:str = Depends(cls.deps.get_authorizer(roles=["admin"],access_rules=[])),
            ):

            logging.info(f"Generating models for {client and '' or 'all '}clients " + \
                         f"{client or ''} (preview={preview})")
            mgr = celery_app.manager
            if client and not client in mgr.es.clients:
                raise APIErrorException(404,status="error",reason=f"No such client alias {client}")
            # force True => if we hit the endpoint, we actually to generate the models, no matter what's
            # in the cache
            res = celery_app.send_task("generate_models",
                    kwargs=dict(client=client,preview=preview,force=True))
            resp = get_job_response(res.id,request)
            return resp

        @cls.router.get("/index/models/{alias}",
                description="Return models for given client alias.",
                responses={
                    404:{"model":APIError},
                    401:{"model":NotAuthenticated},
                    403:{"model":Forbidden},
                    },
                tags=["admin"],
                status_code=200)
        def view_models(
                alias:str = Query(...,description="Client alias to visualize the model for"),
                preview:bool = Query(False,description="If True, return the model generated during last dry-run, " + \
                                                       "as a preview. Otherwise return the active model."),
                celery_app = Depends(cls.deps.get_celery_app),
            ):
            mgr = celery_app.manager
            if not alias in mgr.es.clients:
                raise APIErrorException(404,status="error",reason=f"No such client alias {alias!r}")
            # TODO: preview mode
            if preview:
                if not mgr.es.model_provider.has(alias,preview=preview):
                    raise APIErrorException(404,status="error",reason=f"Unable to find model for ES client {alias!r} " + \
                                                                      f"(preview={preview})")
            client = mgr.es.clients[alias]
            return client.doc_class._doc_type.mapping.to_dict()

        @cls.router.delete("/index/models/{alias}",
                description="Delete model generated from given schema alias",
                responses={
                    404:{"model":APIError},
                    401:{"model":NotAuthenticated},
                    403:{"model":Forbidden},
                    },
                tags=["admin"],
                status_code=200)
        def delete_models(
                alias:str = Query(...,description="Client alias to delete the model from"),
                preview:bool = Query(False,description="If True, delete the preview model"),
                celery_app = Depends(cls.deps.get_celery_app),
                _:str = Depends(cls.deps.get_authorizer(roles=["admin"],access_rules=[])),
            ):
            mgr = celery_app.manager
            if not alias in mgr.es.clients:
                raise APIErrorException(404,status="error",reason=f"No such client alias {alias!r}")
            # TODO: preview mode
            if preview:
                if not mgr.es.model_provider.has(alias,preview=preview):
                    raise APIErrorException(404,status="error",reason=f"Unable to find model for ES client {alias!r} " + \
                                                                      f"(preview={preview})")
            client = mgr.es.clients[alias]
            if not client.cfg.dynamic.to_dict():
                raise APIErrorException(400,status="error",reason="Only dynamically generated model can be deleted")
            provider = mgr.es.model_provider(client.cfg,provider_only=True)
            provider.delete(client.alias)

            return {"status": "deleted"}

        @cls.router.put("/index/models/sync",
                description="Update Elasticsearch mapping to match models definitions. Once updated, " + \
                            "the response contains a status report with potential remaining operations " + \
                            "which may not have been able to be applied.",
                responses={
                    404:{"model":APIError},
                    401:{"model":NotAuthenticated},
                    403:{"model":Forbidden},
                    },
                tags=["admin"],
                status_code=200)
        def sync_models(
                diffs:MappingDiffs = None,
                client:str = Query(None,description="Client alias to perform the sync on (all clients by default)"),
                dryrun:bool = Query(False,description="Show operations to perform the sync without applying them"),
                skip_forbidden_op:bool = Query(False,description="Only 'add' operation can be dynamically applied, " + \
                                                "if other operations are found, an error is returned unless this " + \
                                                "parameter is True, in which case these ops are skipped"),
                celery_app = Depends(cls.deps.get_celery_app),
                _:str = Depends(cls.deps.get_authorizer(roles=["admin"],access_rules=[])),
            ):
            mgr = celery_app.manager
            if client and not client in mgr.es.clients:
                raise APIErrorException(404,status="error",reason=f"No such client alias {client}")
            aliases = [client] if client else mgr.es.clients
            resp = {_:None for _ in aliases}
            explicit_diffs = diffs and jsonable_encoder(diffs)["diffs"]
            force = diffs.force if diffs else False
            for alias in aliases:
                client = mgr.es.clients[alias]
                if explicit_diffs:
                    all_diffs = client.check()
                    try:
                        verify_subset_diffs(all_diffs,explicit_diffs)
                    except ForbiddenOperation as e:
                        logging.error("OINALNEAAAAAAA %s" % force)
                        if not force:
                            raise APIErrorException(400,status="error",reason=f"Not a subset of model full diffs: {e}")
                res = None
                if not dryrun:
                    try:
                        # explicit_diffs can be None, if nothing passed in the body, meaning full model sync, not just a
                        # subset
                        res = client.update_mapping(diffs=explicit_diffs,skip_forbidden_op=skip_forbidden_op,ask=False)
                        # diffs again to report remaining ops
                        diffs = client.check()
                    except RequestError as e:
                        reason = f"Unknown Elasticsearch request error: {e}"
                        if e.status_code == 400 and e.error == "mapper_parsing_exception":
                            reason = f"Invalid resulting mapping: {e.info['error']['reason']}"
                        raise APIErrorException(400,status="error",reason=reason)
                    except ForbiddenOperation as e:
                        raise APIErrorException(400,status="error",reason=f"For client '{alias}': {e}")
                    except InvalidJsonPatch as e:
                        raise APIErrorException(400,status="error",reason=f"Invalid JSON patch: {e}")
                    except MappingUpdateError as e:
                        raise APIErrorException(500,status="error",reason=f"For client '{alias}': {e}")

                resp[alias] = {
                    "synced": not diffs and True or False,
                    "remaining-diffs": diffs,
                    "status": (dryrun and "dry-run") or (res and "ok" or "error"),
                }

            return resp

        @cls.router.get("/index/mappings/{alias}",
                description="Return Elasticsearch mapping currently in use for give ES client alias",
                responses={
                    404:{"model":APIError},
                    401:{"model":NotAuthenticated},
                    403:{"model":Forbidden},
                    },
                tags=["admin"],
                status_code=200)
        def view_mappings(
                alias:str = Query(...,description="Client alias to visualize the mappings for"),
                celery_app = Depends(cls.deps.get_celery_app),
            ):
            mgr = celery_app.manager
            if not alias in mgr.es.clients:
                raise APIErrorException(404,status="error",reason=f"No such client alias {alias!r}")
            es_client = mgr.es.clients[alias]
            res = es_client.client.indices.get_mapping(index=es_client.index_name)
            # index_name could be an index, most likely an alias on the frontend side, but the response
            # always contains the resolved index, which we don't necessarily know if frontend uses aliases.
            # we'll just check there's only one index name found in the result
            assert len(res) == 1, f"Expected only one entry, got: {res.keys()}"
            mappings = list(res.values())[0]["mappings"]

            return mappings


        ###########
        # ALIASES #
        ###########

        @cls.router.put("/index/aliases/sync",
                description="Synchronize frontend aliases to backend indices",
                tags=["admin"],
                status_code=200)
        def sync_aliases(
                client:str = Query(None,description="Elastic client alias to perform the sync on (all clients by default)"),
                action:str = Query(None,description="Only allow specific sync operations (eg. `create`, `sync`). " + \
                                                    "Default: all possible operations are performed"),
                celery_app = Depends(cls.deps.get_celery_app),
                _:str = Depends(cls.deps.get_authorizer(roles=["admin"],access_rules=[])),
            ):
            mgr = celery_app.manager
            if client and not client in mgr.es.clients:
                raise APIErrorException(404,status="error",reason=f"No such client: {client!r}")
            try:
                action = 'move' if action == 'sync' else action  # different parameters/meanings
                kw = {'ops': action.split(',')} if action else {}
                mgr.update_es_aliases(clients=client,ask=False,**kw)
                return {"status": "ok"}
            except Exception as e:
                raise APIErrorException(500,status="error",reason=f"Error synchronizing aliases: {e}")


        ######################
        # SNAPSHOTS, BACKUPS #
        ######################

        @cls.router.put("/index/snapshot",
                description="Trigger the creation of snapshot, for all ES clients (default) or specific one",
                responses={
                    404:{"model":APIError},
                    401:{"model":NotAuthenticated},
                    403:{"model":Forbidden},
                    202:{"model":SubmittedJob},
                    },
                tags=["admin"],
                status_code=200)
        def create_snapshot(
                request:Request,
                client:str = Query(None,description="Client alias to create the snapshot for (all clients by default)"),
                celery_app = Depends(cls.deps.get_celery_app),
                _:str = Depends(cls.deps.get_authorizer(roles=["admin"],access_rules=[])),
            ):
            #TODO: do we want to be able to specify the snapshot name? we would need to make sure
            # there's no conflict naming with other API's snapshots sharing the same repository
            mgr = celery_app.manager
            if client and not client in mgr.es.clients:
                raise APIErrorException(404,status="error",reason=f"No such client alias {client}")
            clients = {client: mgr.es.clients[client]} if client else mgr.es.clients
            # collect all indices names (note: we don't snapshot alias, real index only)
            indices = [_.index_name for _ in clients.values()]
            # building a GPRN name for the snapshot
            now = datetime.datetime.now()
            backup_name = "es-snapshot"
            backup_name += client and f"-{client}" or ""
            backup_name += "-indices@{}".format(now.strftime("%Y%m%d_%H%M%S"))
            dgprn = parse_gprn(mgr.es.es_snapshot_gprn)
            dgprn["resource-id"] = backup_name
            gprn = generate_gprn(dgprn)
            logging.info(f"Triggering snapshot creation (name={gprn}) for indices: {indices}")
            res = celery_app.send_task("create_snapshot",
                    kwargs=dict(snapshot_name=gprn,indices=indices))
            resp = get_job_response(res.id,request)

            return resp

        @cls.router.get("/index/snapshots",
                description="List avaiable snapshots in repository",
                tags=["admin"],
                status_code=200)
        def list_snapshots(
                celery_app = Depends(cls.deps.get_celery_app),
                _:str = Depends(cls.deps.get_authorizer(roles=["admin"],access_rules=[])),
            ):
            mgr = celery_app.manager
            try:
                res = mgr.es.list_snapshots()
                # filter to minimal informational fields to keep the response readable
                # (get_snapshot() in the other endpoint would return all fields if necessary)
                res["count"] = len(res["snapshots"])
                for i,record in enumerate(res["snapshots"]):  # in-place
                    newrec = {k:v for k,v in record.items() if k in \
                                    ("snapshot","state","start_time","end_time","duration_in_millis",
                                     "indices","failures")}
                    res["snapshots"][i] = newrec

                return res

            except NotFoundError:
                raise APIErrorException(404,status="error",reason="No snapshots found")

        @cls.router.get("/index/snapshots/{name:path}",
                description="Return information about a specific snapshot",
                tags=["admin"],
                status_code=200)
        def show_snapshot(
                name:str = Query(...,description="Snapshot name (usually a GPRN format)"),
                celery_app = Depends(cls.deps.get_celery_app),
                _:str = Depends(cls.deps.get_authorizer(roles=["admin"],access_rules=[])),
            ):
            mgr = celery_app.manager
            try:
                return mgr.es.get_snapshot(name)
            except NotFoundError:
                raise APIErrorException(404,status="error",reason=f"No such snapshot: {name}")


        @cls.router.delete("/index/snapshots/{name:path}",
                description="Delete an existing snapshot",
                tags=["admin"],
                status_code=202)
        def delete_snapshot(
                name:str = Query(...,description="Snapshot name (usually a GPRN format)"),
                celery_app = Depends(cls.deps.get_celery_app),
                _:str = Depends(cls.deps.get_authorizer(roles=["admin"],access_rules=[])),
            ):
            mgr = celery_app.manager
            try:
                res = mgr.es.delete_snapshot(name)
                return {
                    "snapshot": name,
                    "status": "deleted",
                    "result": res
                }
            except NotFoundError:
                raise APIErrorException(404,status="error",reason=f"No such snapshot: {name}")


