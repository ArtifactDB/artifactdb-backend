from typing import Any, List, Union, Optional
import json

from pydantic import BaseModel, Field
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from fastapi import APIRouter
from elasticsearch_dsl.response import Response

from artifactdb.db.elastic.models import ArtifactDBDocumentBase
from artifactdb.db.elastic import AUTH_FIELDS


class ResourceBase:
    """
    Wrapper over FastAPI routes initialization.
    Allows to inject dependency manager coming from the
    application, into this lib-level class.
    """
    # will be set by API application, in register_resources()
    router = None
    deps = None

    @classmethod
    def activate_routes(cls):
        raise NotImplementedError("Implement me in sub-class")


# Custom Exceptions

class ValidationError(Exception):
    pass


class APIErrorException(Exception):
    def __init__(self, status_code, status, reason):
        self.status_code = status_code
        self.status = status
        self.reason = reason


# Models

class APIError(BaseModel):
    status_code: int
    status: str
    reason: str

class SubmittedJob(BaseModel):
    job_id: str
    path: str
    job_url: str = Field(description="URL to check job status")
    status: str = Field("accepted",description="job status upon submission")

class NotAuthenticated(BaseModel):
    detail: str

class Forbidden(BaseModel):
    detail: str

class UploadInstructions(BaseModel):
    project_id:str = Field(description="Project ID for which pre-signed URLs were requested")
    version:str = Field(description="Version for which pre-signed URLs were requested")
    revision:str = Field(description="Suggested revision number (ie. incremented from previous revision)")
    presigned_urls:dict = Field({},description="For each requested filenames (keys), associated pre-signed URL used for upload")
    sts:dict = Field({},description="STS credentials (AWS access key, secret and session token), along with expiration time")
    links:dict = Field(description="Report filenames for which a link has been created, due to duplicated data detection")
    complete_before:str = Field(description="ISO8601 format date by which upload should be marked as completed")
    completion_url:str = Field(description="Endpoint to use (method PUT) to mark uploads as completed")
    abort_url:str = Field(description="Endpoint to use (method PUT) to abort upload")
    purge_job_id:str = Field(description="Scheduled Job ID in charge of purging uncompleted uploads")
    expires_in:str = Field(None,description="Date at which the data will expire (transient)")
    expires_job_id:Optional[Union[None, str]] = Field(None,description="Scheduled Job ID in charge of expiring (deleting) artifacts")

class AbortReport(BaseModel):
    project_id:str = Field(description="Project ID for which abort was requested")
    version:str = Field(description="Version in that project")
    cancel_purge_job_id:str = Field(None,description="Task ID in charge of cancelling the purging task, if any")
    cancel_expires_job_id:str = Field(None,description="Task ID in charge of cancelling the expiring task, if any")
    unlocked:dict = Field(None,description="Information about the lock which was released, if any")

# Custom Responses

class PrettyJSONResponse(JSONResponse):

    def render(self, content: Any) -> bytes:
        return json.dumps(
            content,
            ensure_ascii=False,
            allow_nan=False,
            indent=4,
            separators=(",", ":"),
        ).encode("utf-8")


class ElasticsearchJSONResponse(PrettyJSONResponse):

    def __init__(self, fields=None, *args, **kwargs):
        self._scroll = None
        self.fields = fields
        # if fields are passed, these can be filtered out unless explicitly asked for
        # (index_name is dynamically injected there in class, it's not coming from ES)
        self.filtered = AUTH_FIELDS.union(["_extra.index_name"])
        super().__init__(*args,**kwargs)
        if self._scroll:
            self.headers["link"] = "<%s>; rel=more" % self._scroll

    def clean(self, doc, remove_fields):
        if not doc:
            # this happens when doc has no permissions at all
             # (like during tests, we don't to crash for that at last line
            return
        for unwanted in remove_fields:
            if "." in unwanted:
                dots = unwanted.split(".")
                root = dots[0]
                if root not in doc:
                    continue
                rest = ".".join(dots[1:])
                self.clean(doc[root],[rest])
                if not doc[root]:
                    doc.pop(root)
            else:
                doc.pop(unwanted,None)

    def clean_fields(self, content):
        # did we ask for specific fields, but also added fields for authentication?
        # ex: fields=["project_id"], and AUTH_FIELDS=["owners","viewers"]
        #     All 3 fields will be returned, but we need to remove auth_fields
        #     because original query didn't ask for them
        fields = self.fields or []
        # determine which fields should be removed from results
        # (but only if specific fields were requested, otherwise we return all of them)
        to_remove = self.filtered.difference(set(fields)) or []
        for doc in content["results"]:
            self.clean(doc,to_remove)

    def format_results_from_response(self, results):
        docs = []
        for hit in results.hits:
            doc = hit.to_dict()
            doc["_extra"]["index_name"] = hit.meta.index
            doc = jsonable_encoder(doc)
            docs.append(doc)

        return {"results" : docs, "count": len(docs), "total": results.hits.total["value"]}

    def format_results_from_dict(self, results):
        total = results["hits"].get("total",{}).get("value",0)
        docs = []
        for hit in results["hits"]["hits"]:
            doc = hit
            # _source is present when ES is serving documents straight from
            # a search, without
            if hit.get("_source"):
                doc = hit["_source"]  # replacing with actual ES doc
                if not "_extra" in doc:  # an old doc, old format?
                    doc["_extra"] = {}
                doc["_extra"]["index_name"] = hit["_index"]
            doc = jsonable_encoder(doc)
            docs.append(doc)
        json_results = {"results" : docs, "count": len(docs), "total": total}
        self.set_scroll(json_results,len(docs),results)

        return json_results

    def set_scroll(self, json_results, count, es_results):
        """
        Enrich json_results (final response) with scroll information,
        if any, according to a combination of count compared to total
        results, and whether we have explicit scroll ID in es_results.
        """
        # either we have more results to come, or we have a custom scroll
        # ES scroll: are always there, even if no more data. so we check if total > count
        # custom scroll: we generated it because we know there's more data, whatever total > count is
        # (when search latest, total is not accurate + we generate our own scroll ID)
        total = es_results["hits"].get("total",{}).get("value",0)
        if (total > count) or es_results.get("_custom_scroll_id"):
            # custom scrolls (not generated by ES, but by us) have precedence
            scroll_id = es_results.get("_custom_scroll_id") or es_results.get("_scroll_id")
            next_uri = "/scroll/%s" % scroll_id
            json_results["next"] = next_uri
            self._scroll = next_uri

    def format_document(self, doc):
        result  = doc.to_dict()
        result["_extra"]["index_name"] = doc.meta.index
        result = jsonable_encoder(result)

        return result

    def render(self, content: Any) -> bytes:
        self.init_headers()
        results = content
        if isinstance(results, Response):
            # coming from DSL query
            content = self.format_results_from_response(results)
        elif isinstance(results,dict):
            # coming from "raw" query
            content = self.format_results_from_dict(results)
        elif isinstance(results,ArtifactDBDocumentBase):
            content = self.format_document(results)
        if not self.fields is None:
            self.clean_fields(content)
        content = super().render(content=content)
        self.init_headers()
        return content

