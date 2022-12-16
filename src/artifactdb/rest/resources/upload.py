# pylint: disable=unused-argument,no-member,broad-except
import logging
from typing import List, Union
import datetime
import time
import base64
from urllib.parse import urlparse, urlunparse, urlencode
from enum import Enum
import re

import tzlocal
from fastapi import Depends, Query, Request
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field

from artifactdb.rest.resources import APIErrorException, APIError, NotAuthenticated, UploadInstructions, \
                                      Forbidden, ResourceBase, ValidationError
from artifactdb.backend.utils import META_FOLDER
from artifactdb.utils.stages import INDEXED, MODIFIED, PURGED, FAILED
from artifactdb.utils.misc import get_root_url, dateparse
from artifactdb.backend.components.locks import ProjectLockedError
from artifactdb.backend.components.storages import InvalidLinkError
from artifactdb.utils.context import storage_default_client_context
from artifactdb.rest.helpers import get_sts_credentials, open_log_request
from artifactdb.db.elastic.manager import NotFoundError


class FileDedupInfo(BaseModel):
    filename:str = Field(...,description="Filename to upload")
    check:str = Field(...,description="Type of check performed for deduplication, one of: md5 (md5 checksum), "
                          + "size_mdtm (size and last modified timestamp), link (force the file to be a link")
    value:dict = Field(...,description="Value associated to the check. Format:\n"
                           + "md5: {'field': 'field in docs containing the md5sum (can use dotfield notation "
                           + "for inner field), 'md5sum': <actual checksum value>}\n"
                           + "size_mdtm: {'size': <bytes>, 'mdtm': <epoch seconds (utc)>}, "
                           + "link: {'artifactdb_id': <ArtifactDB identifier>}")

class UploadMode(str,Enum):
    S3_PRESIGNED_URL = "s3-presigned-url"
    STS_CREDENTIALS = "sts-credentials"


class UploadContract(BaseModel):
    """
    Describes what client will upload and by when it'll be completed
    """
    filenames: List[Union[str,FileDedupInfo]] = Field(...,
                            description="List of filenames to upload, as strings (paths) "
                            + "or FileDedupInfo dict if deduplication is required (in that case, "
                            + "passed informations are used to determine if the file should be "
                            + "uploaded (new) or linked to a files in a previous version (duplicate)",
                            min_length=1)
    completed_by:str = Field(None,
                            description="Date by which all requested documents will be uploaded "
                            + "(that is, when upload is done). Relative dates such as `in 5 days`, or "
                            + "`in 48 seconds`, or `July 4, 2020 PST` are allowed. Max delay is 5 days (default "
                            + "is 1 day if not specified). If upload is not marked as completed before that date, "
                            + "they are automatically deleted from the S3 bucket (auto-purge).")
    expires_in:str = Field(None,
                            description="If set, date at which all documents will be deleted, both from S3 "
                            + "and ElasticSearch index. This is way to upload temporary, or transient artifacts")

    mode:UploadMode = Field(UploadMode.S3_PRESIGNED_URL,
                            description=f"Uploading mode. '{UploadMode.S3_PRESIGNED_URL}' will return one URL per file, "
                            + f"implying a file size limitation to 5GB. '{UploadMode.STS_CREDENTIALS}' will return "
                            + "temporary AWS credentials (access key, secret key, session token) allowing bigger files "
                            + "(up to 5TB) using multipart uploads, which also allows parallel uploads. It's "
                            + "recommended to use a AWS provided library to manage uploads with "
                            + f"'{UploadMode.STS_CREDENTIALS}', such as `boto3`. Finally, if files are "
                            + f"bigger than 100MB, '{UploadMode.STS_CREDENTIALS}' mode is recommended.")
    class Config:
        schema_extra = {
            "example": {
                "filenames" : ["bla.txt","folder/bla2.csv"],
                "completed_by": "in 10 minutes",
                "mode": f"{UploadMode.S3_PRESIGNED_URL}",
            }
        }

def get_link_path(project_id, version, filename, target_aid):
    src = base64.b64encode(f"{project_id}:{filename}@{version}".encode()).decode()
    tgt = base64.b64encode(target_aid.encode()).decode()
    return f"/link/{src}/to/{tgt}"

# Helpers to generate presigned URL for new uploaded files
# or link instruction URL for duplicated files
def get_presigned_url(s3, project_id, version, filename, presigned_ttl):
    key = "%s/%s/%s" % (project_id,version,filename)
    if META_FOLDER in key:
        raise APIErrorException(
            status_code=403,
            status="error",
            reason="Found reserved name '{}' in path '{}'".format(META_FOLDER,key))
    logging.debug("Requesting pre-signed URL to upload %s" % key)
    url = s3.get_presigned_url_for_upload(key,expires_in=presigned_ttl)
    return url

# Helpers for deduplication methods
def md5_matches(es, project_id, version, info):
    # we search within a project, not outside (no cross-link between projets' resources)
    # though we could just using the md5sum. but then, the size_mdtm check wouldn't be symmetrical
    # as we'd potentially find lots of files with the size and mdtm. There's also a possility
    # of hash collision that is limited within a project compared to the whole artifact db
    field = info.value["field"]
    kwargs = {"_extra.project_id": project_id, field: info.value["md5sum"], "path": info.filename}
    try:
        results = es.search_by(**kwargs)
        hits = results["hits"]["hits"]
        if hits:
            # to limit the chain of redirection:
            # 1. eliminate docs which are already links to the source
            filtered = filter(lambda e: not e["_source"]["_extra"].get("link_aid",None),hits)
            # 2. find the oldest doc, (the oldest is probably, the original
            # one the others are pointing to)
            shits = sorted(filtered,key=lambda e: e["_source"]["_extra"].get("uploaded",""),reverse=True)
            return shits[0]["_source"]
    except NotFoundError:
        # no match
        return None

def check_valid_link(es, project_id, version, info):
    # explicit link instructions, make sure target exists (and while doing so,
    # that auth user has permissions to access the file
    target_id = info.value["artifactdb_id"]
    doc = es.fetch_by_id(target_id)
    if not doc:
        raise InvalidLinkError(f"{target_id} doesn't exist (or permission denied)")

    return doc

def generate_url(cfg, request, uri_path):
    # either it's hard coded in confing (unlikely)
    # or we take it from the request
    root_url = cfg.root_url
    if not root_url:
        root_url = get_root_url(request)
    return root_url + uri_path

def get_link_or_presigned_url(s3, es, cfg, request, project_id, version, filededupinfo, presigned_ttl):
    # go through the mode to validate content
    info = FileDedupInfo(**filededupinfo)
    check_type = info.check.lower()
    source_aid = f"{project_id}:{info.filename}@{version}"
    target = None
    url = None
    is_link = False
    if check_type == "md5":
        target = md5_matches(es,project_id,version,info)
    elif check_type == "size_mdtm":
        raise NotImplementedError("size_mdtm method not implemented (yet)")
        ###target = size_mdtm_match(info)
    elif check_type == "link":
        target = check_valid_link(es,project_id,version,info)
    else:
        raise ValidationError(f"'{check_type}' is not a valid check",)
    if target:
        target_aid = target['_extra']['id']
        if target_aid == source_aid:
            logging.warning(f"Duplicate pointing to self (re-uploading '{target_aid}'?)")
            is_link = False
            url = get_presigned_url(s3,project_id,version,info.filename,presigned_ttl)
        else:
            logging.info(f"Found duplicate {source_aid} => {target_aid}")
            uri_path = get_link_path(project_id,version,info.filename,target_aid)
            url = uri_path
            is_link = True
    else:
        url = get_presigned_url(s3,project_id,version,info.filename,presigned_ttl)

    return is_link,url


class UploadResource(ResourceBase):


    @classmethod
    def activate_routes(cls):

        ##########
        # UPLOAD #
        ##########
        @cls.router.post("/projects/{project_id}/version/{version}/upload",
                           description="Return a list of pre-signed URLs for given project/version. These URLs can be used "
                                       + "to upload artifact files, for a limited amount of time (derived from `completed_by`). "
                                       + "A list of filenames that need to be uploaded must be provided. Upon upload using URLs, "
                                       + "files will be uploaded to the S3 bucket, under folder `/<project_id>/<version>/`.",
                           response_description="List of URLs for each request filenames",
                           responses={
                               400: {"model": APIError},
                               423: {"model": APIError},  # locked, status is for WebDAV, but I like it...
                               200: {"model": UploadInstructions},
                               401: {"model": NotAuthenticated},
                               403: {"model": Forbidden},
                           },
                           tags=["projects"],
                           status_code=200)
        async def upload_files_to_project(
            request: Request,
            contract: UploadContract,
            project_id: str = Query(..., description="Project ID", example="GPA2"),
            version: str = Query(..., description="version under given project",
                                 example="0309292e3494e98290b6d1c2350449315683f381"),
            es=Depends(cls.deps.get_es_client),
            s3=Depends(cls.deps.get_s3_client),
            cfg=Depends(cls.deps.get_cfg),
            lock_manager=Depends(cls.deps.get_lock_manager),
            presign_mgr=Depends(cls.deps.get_presign_manager),
            celery_app=Depends(cls.deps.get_celery_app),
            auth: str = Depends(cls.deps.get_authorizer(roles=["uploader"], access_rules=["write_access"])),
        ):
            try:
                # try to lock the project in "uploading" stage
                lock_manager.lock(project_id, stage="uploading")
                # if we get there, it means we could lock it, so if
                # anything goes wrong after this point, we need to release the lock

                completed_by = contract.completed_by
                min_delay = "in 10 seconds"
                default_delay = "in 1 day"
                max_delay = "in 5 days"
                completed_by = completed_by or default_delay
                max_dt = dateparse(max_delay)
                min_dt = dateparse(min_delay)
                purge_dt = dateparse(completed_by)
                if purge_dt is None:
                    raise APIErrorException(status_code=400, status="error",
                                            reason="Can't parse completed_by date '{}'".format(completed_by))

                purge_dt = min(purge_dt, max_dt)
                purge_dt = max(purge_dt, min_dt)

                # Generate pre-sign URLs and link instructions
                instructions = {}
                urls = {}
                links = {}
                upload_ttl = round(purge_dt.timestamp() - time.time())
                for filename in contract.filenames:
                    url = None
                    # return presigned for each file if in presigned URL mode
                    if isinstance(filename, str):
                        if contract.mode == UploadMode.S3_PRESIGNED_URL:
                            url = get_presigned_url(s3, project_id, version, filename, upload_ttl)
                            urls[filename] = url
                        else:
                            # upload will be handled with STS creds, no need to generate a URL
                            pass
                    else:
                        # whatever the mode (presigned vs. sts), we still return URL to link data...
                        try:
                            filededupinfo = jsonable_encoder(filename)
                            is_link, url = get_link_or_presigned_url(s3, es, cfg, request, project_id, version,
                                                                     filededupinfo, upload_ttl)
                            filename_key = filededupinfo["filename"]
                            if is_link:
                                # identified as "same file" so link url
                                links[filename_key] = url
                            elif contract.mode == UploadMode.S3_PRESIGNED_URL:
                                # looks like different files, so real pre-signed URLs
                                urls[filename_key] = url

                        except ValidationError as e:
                            raise APIErrorException(status_code=422, status="error",
                                                    reason=f"Invalid deduplication info: {e}")
                        except InvalidLinkError as e:
                            raise APIErrorException(status_code=400, status="error",
                                                    reason=f"Invalid link: {e}")
                    if url is None:
                        logging.warning(f"Not giving upload instructions for {filename}")
                        continue

                # Build /complete and /abort URLS
                completion_url = f"/projects/{project_id}/version/{version}/complete"
                completion_qs = {}
                # add suggested revision
                revision = celery_app.manager.revision_manager.get_next_revision(project_id)
                completion_qs["revision"] = revision

                logging.info(
                    "Scheduling auto-delete task if not completed on time (purge_not_completed, eta: %s)" % purge_dt)
                purge_job_id = celery_app.send_task("purge_not_completed",
                                   kwargs={
                                       "project_id": project_id,
                                       "version": version,
                                       "storage_alias": storage_default_client_context.get(),
                                   },
                                   eta=purge_dt
                               )
                completion_qs["purge_job_id"] = purge_job_id

                # transient/expiration
                expires_dt = None
                expires_job_id = None
                expires_in = contract.expires_in
                if expires_in:
                    expires_dt = dateparse(expires_in)
                    if expires_dt is None:
                        raise APIErrorException(status_code=400, status="error",
                                                reason="Can't parse expires_in date '{}'".format(expires_in))
                    if expires_dt < purge_dt:
                        raise APIErrorException(status_code=400, status="error",
                                                reason="'expires_in' ({}) must be greater than 'completed_by' ({})".format(
                                                    expires_dt, purge_dt))
                    logging.info("Scheduling expiration task, all data will be deleted by {}".format(expires_dt))
                    expires_job_id = celery_app.send_task("purge_expired",
                                         kwargs={
                                             "project_id": project_id,
                                             "version": version,
                                             "storage_alias": storage_default_client_context.get()
                                         },
                                         eta=expires_dt
                                     )
                    completion_qs["expires_job_id"] = expires_job_id
                    completion_qs["expires_in"] = expires_dt.isoformat()

                completion_parsed = urlparse(completion_url)
                # add encoded query string
                completion_parsed = completion_parsed._replace(query=urlencode(completion_qs))
                completion_url = urlunparse(completion_parsed)

                # Build /abort URL from /complete
                # not useful for /abort
                completion_qs.pop("expires_in",None)
                completion_qs.pop("revision",None)
                abort_path = re.sub(r"/complete$","/abort",completion_parsed.path)
                abort_parsed = urlparse(abort_path)._replace(query=urlencode(completion_qs))
                abort_url = urlunparse(abort_parsed)

                # if the API has a pre-sign manager, it probably means it has `/projects/upload` and `/projects/{pid}/upload` available,
                # which means we need to temp. give access to the /complete endpoint. Pre-sign URL' TTL must be the same
                # as complete_before to be consistent.
                if presign_mgr:
                    pre_sign_ttl = (purge_dt - datetime.datetime.now(tz=tzlocal.get_localzone())).seconds
                    completion_url = presign_mgr.generate("PUT", completion_url, user=auth, ttl=pre_sign_ttl)
                    abort_url = presign_mgr.generate("PUT", abort_url, user=auth, ttl=pre_sign_ttl)
                    root_url = get_root_url(request)
                    for filename,link_url in links.items():
                        signed = presign_mgr.generate("PUT", link_url, user=auth, ttl=pre_sign_ttl)
                        links[filename] = f"{root_url}{signed}"

                if contract.mode == UploadMode.S3_PRESIGNED_URL:
                    instructions["presigned_urls"] = urls
                else:
                    assert contract.mode == UploadMode.STS_CREDENTIALS
                    sts = await get_sts_credentials(
                        celery_app.manager,
                        project_id,
                        version,
                        ttl=upload_ttl,
                        mode="readwrite",
                    )
                    instructions["sts"] = sts

                instructions.update({
                    "project_id": project_id,
                    "version": version,
                    "revision": str(revision),
                    "links": links,
                    "complete_before": purge_dt.isoformat(),
                    "completion_url": completion_url,
                    "abort_url": abort_url,
                    "purge_job_id": str(purge_job_id),
                    "expires_in": expires_dt and expires_dt.isoformat(),
                    "expires_job_id": expires_job_id and str(expires_job_id),
                })

                await open_log_request(
                    celery_app,
                    project_id=project_id,
                    version=version,
                    # each "close_when" matches the resulting event in "attrs_when_closed"
                    close_when=[{"stage": INDEXED},{"stage": FAILED},{"stage": PURGED}],
                    attrs_when_closed=[{"stage": MODIFIED},{"stage": FAILED},{"stage": PURGED}]
                )

                return UploadInstructions(**instructions)

            except ProjectLockedError as e:
                logging.warning("Can't lock project '{}': {}".format(project_id, e))
                lock_info = None
                try:
                    # enrich error with some lock information
                    lock_info = lock_manager.info(project_id)
                except Exception as exc:
                    logging.error("Can't fetch lock info: {}".format(exc))
                raise APIErrorException(
                    status_code=423,
                    status="error",
                    reason="Project '{}' is locked: {}".format(project_id, lock_info))

            except Exception as e:
                logging.exception("Error while processing upload request for project_id {}: {}".format(project_id, e))
                # locked was sucessfuly acquired before the "try", it means it's us who lock it, so we have release it
                lock_manager.release(project_id)  # ,force=True)
                raise
