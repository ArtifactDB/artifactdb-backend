# pylint: disable=invalid-name,redefined-builtin  # `id` as a file ID
import logging
import base64

from pydantic import BaseModel, Field, HttpUrl
from elasticsearch import NotFoundError

from fastapi import Depends, Query
from fastapi.responses import JSONResponse

from artifactdb.rest.resources import APIErrorException, APIError, Forbidden, NotAuthenticated, \
                                 ResourceBase, ElasticsearchJSONResponse
from artifactdb.identifiers.aid import MalformedID
from artifactdb.backend.components.storages import InvalidLinkError


class Redirection(BaseModel):
    id: str = Field(...,description="Requested file ID")
    location: str = Field(...,description="Location URL for the file. This header along with status 302 "
                                          + "is usually enough for an HTTP client to follow links and "
                                          + "automatically access the resource.")

class RedirectionHeader(BaseModel):
    Location: HttpUrl = Field(...,description="Location URL for the file. This header along with "
                                            + "status 302 is usually enough for an HTTP client to follow "
                                            + "links and automatically access the resource.")

class FilesResource(ResourceBase):

    @classmethod
    def activate_routes(cls):

        ############
        # METADATA #
        ############
        @cls.router.get("/files/{id:path}/metadata",
                description="Retrieve the metadata for a particular file",
                response_description="Result file metadata",
                responses={
                    404:{"model":APIError},
                    400:{"model":APIError},
                    401:{"model":NotAuthenticated},
                    403:{"model":Forbidden},
                },
                tags=["files"])
        def file_metadata(
            id:str = Query(...,description="identifier for the desired file " + \
                           "(format:`<project_id>:<path>@<version|revision>`). " +
                           '"latest" or "LATEST" can be used to access the latest available version'),
            follow_link:bool = Query(False,description="If the artifact is a link to another target artifact, " + \
                                     "returns the target metadata"),
            es = Depends(cls.deps.get_es_client),
            _:str = Depends(cls.deps.get_authorizer()),
        ):
            try:
                try:
                    _ = es.parse_id(id)
                except MalformedID as e:
                    raise APIErrorException(400,status="error",reason="Malformed ID: %s" % str(e))
                doc = es.fetch_by_id(id,follow_link=follow_link)
                if not doc:
                    raise NotFoundError(404,"No such file")
                return ElasticsearchJSONResponse(content=doc)
            except NotFoundError as e:
                raise APIErrorException(e.status_code, status="error", reason=e.error)


        ############
        # DOWNLOAD #
        ############
        @cls.router.get("/files/{id:path}",
                description="Retrieve a file. This endpoint doesn't directly serve artifact file "
                + "content, but rather provides a pre-signed URL from which the file can be accessed "
                + "(temporary access). This URL is passed both in the response body and headers (Location:) "
                + "which along with status 302 is usually enough for an HTTP client to follow links and "
                + "automatically access the resource. Also note Swagger interface may complain about not "
                + "being able to fetch data, this is due to the redirection.",
                response_description="Redirection instructions to access the file",
                responses={
                    302:{"model":Redirection, "headers":{"Location":""}},
                    404:{"model":APIError},
                    400:{"model":APIError},
                    401:{"model":NotAuthenticated},
                    403:{"model":Forbidden},
                },
                tags=["files"],
                status_code=302)
        def file_download(
            id:str = Query(...,description="identifier for the desired file (format:`<project_id>:<path>@<version|revision>`)"),
            expires_in:int = Query(120,description="expiration time, in seconds, after which the return link won't be valid " +
                                               "anymore. Default to 120s, minimum; 10s,  max allowed: 86400 (24h)""",
                                   ge=10,le=86400),
            s3=Depends(cls.deps.get_s3_client),
            es=Depends(cls.deps.get_es_client),
            _:str = Depends(cls.deps.get_authorizer()),
        ):
            full_id = id
            try:
                ids = es.parse_id(full_id)
            except MalformedID as e:
                raise APIErrorException(400,status="error",reason="Malformed ID: %s" % str(e))
            # Fetch metadata first. Depending on auth user, we'll get something or not,
            # and if nothing, it means not allowed to download it
            try:
                doc = es.fetch_by_id(full_id,follow_link=True)  # resolve links to download targeted data
                if not doc:
                    raise NotFoundError(404,"No such file")  # caught below
                # check if full_id is the real id or contains a revision
                if doc._extra.id != full_id:
                    # adjust "ids" so it contains the real value for the "version"
                    # not the revision. In the end we should have a valid S3 key
                    # (S3 stores per version, not revision)
                    # More, since the introduction of lins, the whole ID could have changed
                    # (link pointing to a different project, different path, different version)
                    # so we'll just update the whole
                    new_ids = es.parse_id(doc._extra.id)
                    logging.debug(f"Converted {ids} to {new_ids}")
                    ids = new_ids
            except NotFoundError as e:
                # Not found is ok, it just doesn't exist.
                # Different than "not allowed"
                raise APIErrorException(e.status_code,status="error",reason=e.error)
            # if we get there, we passed the test, ie. allowed to pursue
            # obtain a pre-signed URL and redirect
            key = "%(project_id)s/%(version)s/%(path)s" % ids
            url = s3.get_presigned_url(key,expires_in=expires_in)
            headers = {"Location": url}
            content = {"id": full_id, "location" : url}

            return JSONResponse(status_code=302,content=content, headers=headers)

        ###########
        # SYMLINK #
        ###########
        @cls.router.put("/link/{b64_source_id}/to/{b64_target_id}",
                description="Given a source and target ArtifactDB ID (base64 encoded), create a link "
                + "(like a symlink) where source points to the target. User must have owner permissions"
                + "on target ArtifactDB ID, and source project/version. Note: IDs can contains slashes "
                + "and other special chars, and need to be base64 encoded.",
                responses={
                    200:{"model":APIError},
                    404:{"model":APIError},
                    400:{"model":APIError},
                    401:{"model":NotAuthenticated},
                    403:{"model":Forbidden},
                },
                tags=["files"],
                status_code=200)
        def file_link(
            b64_source_id: str = Query(...,description="Source ArtifactDB ID"),
            b64_target_id: str = Query(...,description="Target ArtifactDB ID"),
            s3=Depends(cls.deps.get_s3_client),
            es=Depends(cls.deps.get_es_client),
            _:str = Depends(cls.deps.get_authorizer(roles=["uploader"],access_rules=["write_access"]))
        ):
            # sanity check: linking to self not allowed
            if b64_source_id == b64_target_id:
                raise APIErrorException(400,status="error",reason="Source and target ArtifactDB IDs are the same, "
                                                                + "self-linking not allowed")
            try:
                source_id = base64.b64decode(b64_source_id).decode()
                target_id = base64.b64decode(b64_target_id).decode()
            except Exception as e:
                raise APIErrorException(400,status="error",reason=f"Can't decode ArtifactDB ID: {e}")

            logging.info(f"Requesting link '{source_id}' => '{target_id}'")

            # properly formed IDs
            try:
                _ = es.parse_id(source_id)
                target_ids = es.parse_id(target_id)
            except MalformedID as e:
                raise APIErrorException(400,status="error",reason=f"Malformed ArtifactDB ID: {e}")

            # version/revision can resolve
            target_version = es.convert_revision_to_version(target_ids["project_id"],target_ids["version"])
            if target_version is None:
                raise APIErrorException(404,status="error",
                                        reason="Can't find target version or revision "
                                             + f"'{target_ids['version']}' (or permission was denied)")
            # Note: for source permission check, either user is an uploader (role) or has write_access
            # (on the version itself if it already exists, or at the project-level)
            # so at this point, we can create a link there.
            # For the target file, we check if user has permissions on that file.
            # If later permissions on the target file change, user will still have access to it, because
            # during the creation of the link, he once had those permissions. IOW there's no later sync
            # of permissions (and it would be confusing for the user who would suddenly loose his permissions)
            doc = es.fetch_by_id(target_id)
            if not doc:
                raise APIErrorException(404,status="error",
                                        reason=f"Target file {target_id} doesn't exist "
                                              + "or permission was denied")
            # all good, create the link
            try:
                s3.create_link(source_id,target_id)
            except InvalidLinkError as e:
                raise APIErrorException(400,status="error",
                                        reason=str(e))
            except Exception as e:
                logging.exception(e)
                raise


