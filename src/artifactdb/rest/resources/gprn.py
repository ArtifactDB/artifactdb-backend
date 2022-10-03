import logging

from pydantic import BaseModel, Field, conlist

from fastapi import Depends, Query
from elasticsearch.exceptions import RequestError
from nested_lookup import nested_lookup

from artifactdb.rest.resources import APIErrorException, ResourceBase
from artifactdb.identifiers.aid import MalformedID, unpack_id, generate_key, pack_id
from artifactdb.identifiers.gprn import FormatError, UnsupportedTypeID, GPRNError, validate as validate_gprn, \
                                        parse_resource_id, get_parents, generate as generate_gprn, \
                                        unparse_resource_id, NoSuchGPRN, build as build_gprn


def get_children(gprn, cfg, es):
    """Return all children of given gprn"""
    parsed = validate_gprn(gprn, cfg.gprn)
    if parsed["type-id"] == "artifact":  # return nothing because there is no children
        raise GPRNError("GPRN with type-id 'artifact' can't have children")
    if parsed["type-id"] == "doc":  # for now, return doc url
        return {
            'doc': cfg.doc_url
        }
    if parsed["type-id"] == "changelog":  # for now, return changelog url
        return {
            # TODO: this should be taken from the / endpoint (resource info)
            'changelog': "...",
        }
    resource_id = parse_resource_id(parsed["type-id"], parsed["resource-id"])
    if not resource_id:
        # scroll implementation not done, for now use search endpoint with partial result flag.
        # if asking for children of all project for instance, it's too long so it's 400 for now
        raise APIErrorException(400, status="error",
                reason="Requesting children without a resource-id component is not allowed (for now)")
    size = cfg.gprn.extra['max_children']  # return max number of children
    q = f"_extra.project_id:{resource_id['project_id']}"
    if resource_id.get("version"):
        q += f"AND _extra.version:{resource_id['version']}"
    results = es.search(q, fields="_extra.gprn", size=size)
    if results and results["hits"]["hits"]:
        gprn_results = nested_lookup("gprn", results)
        values = {
            'children': gprn_results
        }
        if results.get('_custom_scroll_id'):  # flag to indicate there are more children available.
            values['partial_results'] = True
        return values
    else:
        raise APIErrorException(404, status="error", reason="No GPRNs found")


class Gprns(BaseModel):
    gprns: conlist(str, max_items=1000) = Field(...,description="GPRNs list")
    class Config:
        schema_extra = {
            "example": {
                "gprns" : ["gprn1", "gprn2", "gprn3"],
            }
        }


def check_gprn(gprn, cfg, es):
    parsed = validate_gprn(gprn, cfg.gprn)
    resource_id = parse_resource_id(parsed["type-id"], parsed["resource-id"])
    found = None
    if not resource_id:
        raise APIErrorException(400, status="error",
                reason="Requesting permissions without a resource-id component is not allowed")
    if parsed["type-id"] == "artifact":
        found = es.fetch_by_id(parsed["resource-id"],follow_link=True)
    elif parsed["type-id"] == "project":
        # version could be None
        es_results = es.search_by_project_id(resource_id["project_id"],resource_id.get("version"))
        # search results, check the hits
        found = es_results and es_results["hits"]["hits"]

    return bool(found)


def find_links(es, s3, cfg, resource_id, check):
    links = []
    project_id = resource_id["project_id"]
    version = resource_id.get("version")
    for info in es.find_links(project_id,version):
        if not "artifactdb" in info["link"]:
            raise APIErrorException(400, status="error",
                    reason="Unsupporter link type: {}".format(info))
        ids = unpack_id(info["id"])
        link_info = {
            "key": generate_key(ids),
            "location": {
                "s3_url": None,
                "s3_arn": None,
            }
        }
        if info["link"]["artifactdb"]:
            link_ids = unpack_id(info["link"]["artifactdb"])
            gprn_link = build_gprn(cfg.gprn,**link_ids)
            s3_url_link = s3.get_s3_url(gprn_link,gprn_cfg=cfg.gprn,check=check)
            s3_arn_link = s3.get_s3_arn(cfg.s3.bucket,**link_ids)
            link_info["location"]["s3_url"] = s3_url_link
            link_info["location"]["s3_arn"] = s3_arn_link
        else:
            logging.warning(f"Found broken link: {info}")
        links.append(link_info)

    return links



class GPRNResource(ResourceBase):

    @classmethod
    def activate_routes(cls):

        ############
        # VALIDATE #
        ############
        @cls.router.get("/gprn/{gprn:path}/validate",
                          description="Check if given gprn is valid or not",
                          tags=["gprn"])
        def validate(
            gprn: str = Query(..., description="GPRN"),
            cfg=Depends(cls.deps.get_cfg),
        ):
            try:
                _ = validate_gprn(gprn, cfg.gprn)
                return {
                    'status': "ok"
                }
            except (GPRNError, FormatError, UnsupportedTypeID,MalformedID) as e:
                raise APIErrorException(400, status="error", reason=str(e))


        ##########
        # LOCATE #
        ##########
        @cls.router.get("/gprn/{gprn:path}/locate",
                          description="Returns the s3 URL location for the given gprn",
                          tags=["gprn"])
        def locate(
            gprn:str = Query(..., description="GPRN"),
            check:bool = Query(True,description="Check if corresponding s3 key exists (default)"),
            skip_links:bool = Query(False,description="Bypass link retrieval (time-consuming). Ignored if " + \
                                    "`gprn`is an artifact, in which case the S3 location is always resolved " + \
                                    "to the existing artifact if it's a link."),
            s3=Depends(cls.deps.get_s3_client),
            es=Depends(cls.deps.get_es_client),
            cfg=Depends(cls.deps.get_cfg),
            _: str = Depends(cls.deps.get_authorizer())
        ):
            try:
                parsed = validate_gprn(gprn,cfg.gprn)
                resource_id = parse_resource_id(parsed["type-id"], parsed["resource-id"])
                is_artifact = parsed["type-id"] == "artifact"
                if not resource_id.get("project_id"):
                    raise APIErrorException(400, status="error",
                            reason="Requesting to locate a GPRN without a resource-id component is not allowed")
                if resource_id.get("version"):
                    # it could be a revision, normalize to a version (revisions don't exist on s3)
                    new_version = es.convert_revision_to_version(resource_id["project_id"],resource_id["version"])
                    if new_version is None:
                        if check:
                            raise APIErrorException(404, status="error", reason="No such GPRN (incorrect revision?)")
                        # back to original version, we couldn't convert it but that's fine
                        # since we don't check the existence of that GPRN on S3
                        new_version = resource_id["version"]
                    # build back GPRN with the version
                    resource_id["version"] = new_version
                    parsed["resource-id"] = unparse_resource_id(parsed,resource_id)
                    gprn = generate_gprn(parsed)
                # explore link to also report their s3 locations. If GPRN points to an artifact, we always resolve the
                # link to the actual file on s3. `skip_links` is more useful for project-level GPRNs, when within a
                # given project we want to resolve all links
                links = None
                if not skip_links and not is_artifact:
                    links = find_links(es,s3,cfg,resource_id,check=check)
                if is_artifact:
                    aid = pack_id(resource_id)
                    doc = es.fetch_by_id(aid,follow_link=True)
                    if not doc:
                        raise NoSuchGPRN(f"Unable to locate GPRN {gprn}, unable to fetch artifact {aid}")
                    if doc._id != aid:
                        logging.debug(f"Resolving link {aid} => {doc._id}")
                        # override previous variables: parsed, gprn, resource_id
                        parsed["resource-id"] = doc._id
                        gprn = generate_gprn(parsed)
                        resource_id = parse_resource_id(parsed["type-id"], parsed["resource-id"])

                # core data, within project/version
                s3_url = s3.get_s3_url(gprn,gprn_cfg=cfg.gprn,check=check)
                s3_arn = s3.get_s3_arn(cfg.s3.bucket,**resource_id)
                return {
                    "s3_url": s3_url,
                    "s3_arn": s3_arn,
                    "links": links,
                    "region": cfg.s3.region,
                }
            except NoSuchGPRN as e:
                raise APIErrorException(404, status="error", reason=str(e))
            except (GPRNError, FormatError, UnsupportedTypeID, MalformedID) as e:
                raise APIErrorException(400, status="error", reason=str(e))


        ############
        # CHILDREN #
        ############
        @cls.router.get("/gprn/{gprn:path}/children",
                          description="Returns the children for the given gprn",
                          tags=["gprn"])
        def children(
            gprn: str = Query(..., description="GPRN"),
            es=Depends(cls.deps.get_es_client),
            cfg=Depends(cls.deps.get_cfg),
            _: str = Depends(cls.deps.get_authorizer())
        ):
            try:
                children = get_children(gprn, cfg, es)
                return children
            except (GPRNError, FormatError, UnsupportedTypeID, RequestError, MalformedID) as e:
                raise APIErrorException(400, status="error", reason=str(e))


        ###########
        # PARENTS #
        ###########
        @cls.router.get("/gprn/{gprn:path}/parents",
                          description="Returns the parents of given gprn",
                          tags=["gprn"])
        def parents(
            gprn: str = Query(..., description="GPRN"),
            deep: bool = Query(False, description="Get all possible parents"),
        ):
            try:
                return get_parents(gprn, deep=deep)
            except (GPRNError, FormatError, UnsupportedTypeID, MalformedID) as e:
                raise APIErrorException(400, status="error", reason=str(e))


        ###############
        # PERMISSIONS #
        ###############
        @cls.router.get("/gprn/{gprn:path}/permissions",
                          description="Returns whether user can access GPRN (200) or not (404)",
                          tags=["gprn"])
        def permissions(
            gprn: str = Query(..., description="GPRN"),
            cfg=Depends(cls.deps.get_cfg),
            es=Depends(cls.deps.get_es_client),
            _: str = Depends(cls.deps.get_authorizer())
        ):
            # depending on the type-id component of the GPRN, we need to check metadata access
            # on different location:
            # - type-id: artifact. resource-id assumed to be an artifactdb ID, we fetch_by_id(aid)
            # - type-id: project:
            #   * resource-id is a project + version, we search_by_project_id(project_id, version)
            #   * resource-id is a project, no version, we search_by_project_id(project_id,None)
            # - type-id: <anything else>: not allowed, 400
            result = {"allowed": None}
            try:
                result["allowed"] = check_gprn(gprn, cfg, es)
                if not result["allowed"]:
                    raise APIErrorException(404, status="error", reason=f"No such GPRN: '{gprn}'.")
            except (GPRNError, FormatError, UnsupportedTypeID, MalformedID) as e:
                raise APIErrorException(400, status="error", reason=str(e))

            return result


        ####################
        # BULK PERMISSIONS #
        ####################
        @cls.router.post("/gprn/permissions",
                          description="Check permissions for bulk gprns",
                          tags=["gprn"])
        def bulk_permissions(
            gprns: Gprns = None,
            cfg=Depends(cls.deps.get_cfg),
            es=Depends(cls.deps.get_es_client),
            _: str = Depends(cls.deps.get_authorizer())
        ):
            result = {"status": True, "gprns":[] }
            try:
                for gprn in gprns.gprns:
                    is_gprn_allowed = check_gprn(gprn, cfg, es)
                    result["status"] = result["status"] and is_gprn_allowed
                    result["gprns"].append({
                        "gprn": gprn,
                        "allowed": is_gprn_allowed
                    })
            except (GPRNError, FormatError, UnsupportedTypeID, MalformedID) as e:
                raise APIErrorException(400, status="error", reason=str(e))

            return result

