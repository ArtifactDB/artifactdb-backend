from fastapi import Depends, Query, Request
from elasticsearch.exceptions import NotFoundError, RequestError

from artifactdb.db.elastic.client import FieldNotSortable
from artifactdb.db.elastic.manager import NoMoreResultsException
from artifactdb.db.elastic.scrollers import CustomScrollExpired, NoSuchCustomScroll, CustomScrollError
from artifactdb.rest.resources import APIErrorException, APIError, ElasticsearchJSONResponse, \
                                      ResourceBase, PrettyJSONResponse


class InvalidScrollIDError(APIError): pass
class ScrollIDExpiredError(APIError): pass
class NoMoreResultsError(APIError): pass


class SearchResource(ResourceBase):

    @classmethod
    def activate_routes(cls):

        @cls.router.get("/search",
                description="Search for results",
                response_description="Set of results",
                responses={
                    400:{"model":APIError},
                    },
                tags=["search"])
        def search(
            request:Request,
            q:str = Query(...,description="Elasticsearch compatible query string "
                + "(see https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl-query-string-query.html for more)\n"
                + "Ex:\n"
                + "- **specifying fields**: `_extra.project_id:ID1`\n"
                + "- **boolean operations**: `_extra.project_id:ID1 AND _extra.revision:REV-1`\n"
                + "- **fulltext search**: `something`\n"
                + "- **search all**: `*`\n"
                + "- **partial hit**: `someth*`\n"),
            fields:str = Query(None,description="Comma-separated list of fields to specifically return in the results. "
                + "Support \"dotfield\" notation. All fields are returned if omitted."
                + "Ex:\n"
                + "- all fields: `` (default)\n"
                + "- list: `_extra.project_id,_extra.version,_extra.revision`\n"),
            sort:str = Query(None,description="Sort results according to given fields. Note not all fields sortable (see 400 error)\n"
                + "Ex:\n"
                + "- ascending (default): `_extra.project_id`\n"
                + "- descending: `-_extra.project_id`\n"
                + "- multiple fields: `_extra.project_id,-_extra.version`\n"),
            latest:bool = Query(False,description="For each project, returns only the latest revision's files"),
            es=Depends(cls.deps.get_es_client),
            _:str = Depends(cls.deps.get_authorizer()),
        ):

            if fields:
                fields = list(map(str.strip,fields.split(",")))
            if sort:
                sort = list(map(str.strip,sort.split(",")))
            # hidden so user don't fetch too many results at once, instead of using scrolls
            size = request.query_params.get("size")
            try:
                results = es.search(q,fields=fields,sort=sort,latest=latest,size=size)
                return ElasticsearchJSONResponse(content=results,fields=fields)
            except FieldNotSortable as e:
                raise APIErrorException(400,status="error",reason="sort error: %s" % str(e))
            except RequestError as e:
                raise APIErrorException(400,status="error",reason="Query Parse Error: %s" % str(e))
            except ValueError as e:
                raise APIErrorException(400, status="error", reason=str(e))


        @cls.router.get("/aggregate",
                description="Search and aggregate results (see https://www.elastic.co/guide/en/elasticsearch/reference/7.4/search-aggregations.html)",
                response_description="Aggregation results, format varies depending on the aggregation type.",
                responses={
                    400:{"model":APIError},
                    },
                tags=["search"])
        def aggregate(
            q:str = Query(...,description="Elasticsearch compatible query string, same as /search endpoint"),
            agg_field:str = Query(...,description="Field name to aggregate (must support the aggregation type)"),
            agg_type:str = Query("terms",enum=["terms","max"],description="Aggregation type"),
            agg_size:int = Query(50,ge=1,le=500,description="Number of aggregated results (note there's no " + \
                                 "scroll supported for now, so max 500 results is currently allowed)"),
            es=Depends(cls.deps.get_es_client),
            _:str = Depends(cls.deps.get_authorizer()),
        ):
            try:
                agg_name = "aggs"
                response = es.aggregate(q,agg_type=agg_type,agg_field=agg_field,
                                        agg_name=agg_name,agg_size=agg_size)
                agg_results = response["aggregations"][agg_name]
                return PrettyJSONResponse(content=agg_results)
            except RequestError as e:
                raise APIErrorException(400,status="error",reason="Query Parse Error: %s" % str(e))


        @cls.router.get("/scroll/{scroll_id}",
                description=" Continue to fetch results from a previous search query with given scroll ID.",
                response_description="Set of results",
                responses={
                    400:{"model":InvalidScrollIDError},
                    410:{"model":ScrollIDExpiredError},
                    404:{"model":NoMoreResultsError},
                    },
                tags=["search"])
        def scroll(
            scroll_id: str,
            es=Depends(cls.deps.get_es_client),
            _:str = Depends(cls.deps.get_authorizer()),
        ):
            try:
                results = es.scroll(scroll_id=scroll_id, scroll="30s")
                return ElasticsearchJSONResponse(content=results)
            except NoMoreResultsException:
                raise APIErrorException(404,status="error",reason="no more results")
            except (NotFoundError, CustomScrollExpired):
                raise APIErrorException(410,status="error",reason="scroll expired")
            except (RequestError, NoSuchCustomScroll, CustomScrollError):
                raise APIErrorException(400,status="error",reason="invalid scroll_id")

