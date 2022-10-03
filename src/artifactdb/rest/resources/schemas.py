# pylint: disable=invalid-name  # contants...
from urllib.parse import urljoin
from typing import List, Optional

from fastapi.encoders import jsonable_encoder
from fastapi import Depends, Query, Request
from pydantic import BaseModel, Field, validator

from artifactdb.rest.resources import APIErrorException, APIError, ResourceBase, NotAuthenticated, Forbidden
from artifactdb.utils.misc import get_root_url
from artifactdb.db.schema import ValidationError, NoSchemaError, SchemaNotFoundError


class Documents(BaseModel):
    """
    Describes what client will upload in documents
    """
    docs: List[dict] = Field(...,
                            description="List of Documents to validate")
    class Config:
        schema_extra = {
            "example": {
                "docs": [
                    {
                        "source": "bla",
                        "path": "bla.html",
                        "md5sum": "6dfsdfsd88b9053cf3bf79f25a2fsdf",
                        "$schema": "schema/v1.json"
                    }
                ],
            }
        }

    @validator('docs', each_item=True)
    def check_document_not_empty(self, doc):
        if not doc:
            raise ValueError("Empty document are not allowed")
        return doc


def select_schema_client(alias, schema_manager):
    if alias is None:
        return schema_manager  # will aggregate all schemas
    try:
        return schema_manager[alias]
    except KeyError:
        raise APIErrorException(404,status="error",reason=f"No such client alias {alias!r}")


class SchemasResource(ResourceBase):

    @classmethod
    def activate_routes(cls):

        TYPES_ENDPOINT = "/schemas"
        @cls.router.get(TYPES_ENDPOINT,
                    description="Returns list of available document types",
                    tags=["schema"])
        def schema_types(
            request:Request,
            checksum:bool = Query(False,description="Return a checksum computed for a given `client` " + \
                                 "to track if new changes are available and models should be updated " + \
                                 "(needs `admin` role)"),
            schema_manager = Depends(cls.deps.get_schema_manager),
            auth: str = Depends(cls.deps.get_authorizer()),
            client: Optional[str] = None
        ):
            if checksum and not "admin" in auth.roles:
                raise APIErrorException(403,status="error",
                                        reason="Retrieving schema types checksum requires `admin` role")
            schema_client = select_schema_client(client,schema_manager)
            # ask the client to compute the checksum on its schema types
            if checksum:
                result = schema_client.checksum()
                return {"checksum": result}

            results = schema_client.get_types()
            if not results:
                raise APIErrorException(404,status="error",reason="No types found")
            types = []
            url = get_root_url(request) + TYPES_ENDPOINT + "/"
            for result in results:
                if result["name"].startswith("_"):
                    continue
                types.append({
                    "name": result["name"],
                    "url": urljoin(url,result["name"])
                })
            return {"document_types": types}


        VERSIONS_ENDPOINT = "/schemas/{doc_type}"
        @cls.router.get(VERSIONS_ENDPOINT,
                    description="Returns list of available versions for a given document type",
                    responses={404:{"model":APIError}},
                    tags=["schema"])
        def schema_versions(
            request:Request,
            doc_type: str = Query(...,description="Document type",
                                  example="highly_variable_gene_detection"),
            schema_manager = Depends(cls.deps.get_schema_manager),
            client: Optional[str] = None
        ):
            schema_client = select_schema_client(client,schema_manager)
            results = schema_client.get_versions(doc_type)
            if not results:
                raise APIErrorException(404,status="error",reason="Non-existing document type")
            versions = []
            url = get_root_url(request) + VERSIONS_ENDPOINT.format(doc_type=doc_type) + "/"
            for result in results:
                if result["name"].startswith("_"):
                    continue
                version = result["name"].replace(".json","")
                versions.append({
                    "version": version,
                    "url": urljoin(url,version)
                })

            return {
                "document_type": doc_type,
                "versions": versions,
            }


        @cls.router.get("/schemas/{doc_type}/{version}",
                    description="Returns schema for given document type and version",
                    responses={
                        404:{"model":APIError},
                    },
                    tags=["schema"])
        def schema_type_versions(
            doc_type:str = Query(...,description="Document type",
                                 example="highly_variable_gene_detection"),
            version:str = Query(...,description="Schema version",example="v2"),
            schema_manager = Depends(cls.deps.get_schema_manager),
            client: Optional[str] = None
        ):
            if not version.endswith(".json"):
                version += ".json"
            schema_client = select_schema_client(client,schema_manager)
            schema = schema_client.get_schema(doc_type,version)

            if schema is None:
                raise APIErrorException(404,status="error",reason="Non-existing document type or version")

            return schema

        @cls.router.post("/schema/validate",
                          description="Check the given documents are valid or not",
                          responses={
                              404: {"model": APIError}
                          },
                          tags=["schema"])
        def schema_document_validate(
            documents: Documents,
            celery_app=Depends(cls.deps.get_celery_app)
        ):
            try:
                documents = jsonable_encoder(documents)
                celery_app.manager.validate_documents(documents["docs"])
                return {
                    "status": "Documents are valid"
                }
            except (NoSchemaError, SchemaNotFoundError) as e:
                raise APIErrorException(404,status="error",reason="No Schema Found: %s" % str(e))
            except ValidationError as e:
                raise APIErrorException(422,status="error",reason="Document Validation Error: %s" % str(e))
            except TypeError as e:
                raise APIErrorException(400, status="error",reason="%s" % str(e))

        @cls.router.delete("/schema/cache",
                          description="Delete all cache for schemas",
                          responses={
                              401: {"model": NotAuthenticated},
                              403: {"model": Forbidden},
                          },
                          tags=["admin"])
        def delete_cache(
            # no access_rules, strictly sticking to roles
            schema_manager=Depends(cls.deps.get_schema_manager),
            client: Optional[str] = None,
            _: str = Depends(cls.deps.get_authorizer(roles=["admin"], access_rules=[])),
        ):
            try:
                if client:
                    client = schema_manager[client].alias
                # delete all stored cache for schemas
                schema_manager.delete_client_cache(client)
                return {
                    "status": "ok",
                    "message": "Cache deleted"
                }
            except KeyError as e:
                raise APIErrorException(404, status="error", reason="Key not found :: %s" % str(e))

