# pylint: disable=unused-import  # some basics ES classes available to client import
import os
import json
import logging
import math
import copy
from pprint import pformat
from functools import partial

from elasticsearch import Elasticsearch, NotFoundError, ConnectionError  # pylint: disable=redefined-builtin
from elasticsearch.helpers import bulk
from elasticsearch_dsl import Search, Q, connections, Keyword, Text
from luqum.elasticsearch import ElasticsearchQueryBuilder, SchemaAnalyzer

from artifactdb.utils.misc import get_class_from_classpath, iter_batch
from artifactdb.utils.jsonpatch import apply_patch
from artifactdb.utils.jsondiff import make as jsondiff
from .models import Alias
from .import NotAllowedException, DEFAULT_BATCH_SIZE
from .utils import authorize_query, parse_q
from .scrollers import Scroller


class FieldNotSortable(Exception): pass
class AliasNotFound(Exception): pass
class MappingUpdateError(Exception): pass
class ForbiddenOperation(Exception): pass
class TotalFieldsLimitError(Exception): pass


class ElasticClient:

    def __init__(self, alias, cfg, scroll_cfg, model_provider):
        self.alias = alias
        self.cfg = cfg
        self.scroller = Scroller(scroll_cfg)
        self.model_provider = model_provider
        self.use_alias = False  # index_name pointing an alias or a real index?
        self.client_class = get_class_from_classpath(cfg.client_class)
        self.client = self.client_class(
                cfg.uri,
                # one of the standard SSL certs location (used by curl for instance)
                ca_certs=os.environ.get("SSL_CERT_FILE"),
                **cfg.extra,
            )
        if cfg.alias:
            logging.info(f"Alias definition found: {cfg.alias}")
            self.index_name = cfg.alias
            self.use_alias = True
        else:
            self.index_name = cfg.index
        self.doc_class = self.model_provider(self.cfg)
        # register as default connection to avoid having to pass "using=..."
        connections.add_connection("default",self.client)
        # check index exists
        try:
            _ = self.client.indices.get(self.index_name)
        except NotFoundError:
            logging.warning("Index '%s' doesn't exist, now creating",self.index_name)
            self.init()
        except (ConnectionError,ConnectionRefusedError) as e:
            logging.error(f"Unable to connect to Elasticsearch server {self.cfg.uri!r}: {e}")
            raise
        # lazy load query_builder
        self._query_builder = None
        # now runs some sanity check
        self.check()

    def __repr__(self):
        return "<{}.{}: {}/{}>".format(self.__module__,self.__class__.__name__,self.cfg.uri,self.index_name)

    @property
    def query_builder(self):
        if self._query_builder is None:
            schema = self.client.indices.get(self.index_name)
            schema_analyzer = SchemaAnalyzer(schema)
            self._query_builder = ElasticsearchQueryBuilder(**schema_analyzer.query_builder_options())

        return self._query_builder

    def index(self, docs):
        for doc in docs:
            doc.save(using=self.client,index=self.index_name)

    def count_mapping_fields(self, mapping=None):
        """
        Count the number of fields found in `mapping` (or doc_class itself if None).
        This is an estimate, higher than the actual value (which is ok, better more than
        not enough)
        """
        mapping = mapping or self.doc_class._index.to_dict()
        # count all fields recursively, meaning all keys `type`,
        def count_fields(dat, report):
            if isinstance(dat,dict):
                if dat.get("type"):
                    report["count"] += 1
                # continue for each sub-dict
                for v in dat.values():
                    count_fields(v,report)

        report = {"count": 0}
        count_fields(mapping,report)

        return report["count"]

    def estimate_mapping_fields_limit(self, mapping=None):
        count = self.count_mapping_fields(mapping=mapping)
        rounded = int(count * (1 + self.cfg.extra_total_fields_limit_percent))
        total = min(rounded,self.cfg.max_total_fields_limit)
        total = max(total,self.cfg.min_total_fields_limit)
        if total < count:
            raise TotalFieldsLimitError(f"Model needs {count} but max total field limit is " + \
                                        f"{self.cfg.max_total_fields_limit}")
        return total

    def init(self, purge=False):
        """
        Create (and delete first if "purge") an index according to
        a DSL Document class describing fields and indexing rules
        """
        if self.use_alias:
            logging.info("Not performing init because client uses an alias as index name")
            return
        exists = self.index_name in self.client.indices.get("*")
        if purge and exists:
            self.client.indices.delete(self.index_name)
            exists = False
        if not exists:
            # dynamic mapping not allowed, we want to control schema
            index_definition = self.doc_class._index.to_dict()
            total_fields = self.estimate_mapping_fields_limit()
            index_definition["settings"]["mapping"] = {"total_fields": {"limit": total_fields}}

            if index_definition.get('settings'):
                index_definition['settings'].update(self.cfg.index_settings)
            else:
                index_definition['settings'] = self.cfg.index_settings
            res = self.client.indices.create(self.index_name,body=index_definition)
            return res

    def update_mapping(self, diffs=None, skip_forbidden_op=False, ask=True):
        diffs = diffs or self.check()
        if not diffs:
            logging.debug("Not differences found between mapping and model")
            return True

        logging.info("Found following differences:\n{}".format(pformat(diffs)))
        if ask:
            print("Are you sure you want to modify index '{}' and update its mapping? [y/N]".format(self.index_name))
            choice = input().lower()
            if choice not in ["y","yes"]:
                print("Abort")
                return False

        # check we can actually do it
        ops = {d["op"] for d in diffs}
        if not skip_forbidden_op:
            if ops != {"add"}:
                raise ForbiddenOperation(f"Only 'add' ops allowed, found: {ops}")
        else:
            if ops != {"add"}:
                logging.info("Only applying 'add' op")
            diffs = [d for d in diffs if d["op"] == "add"]
        orig_mapping = self.client.indices.get_mapping(self.index_name)[self.index_name]["mappings"]
        logging.debug("Preparing new mapping")
        new_mapping = apply_patch(orig_mapping,diffs)
        logging.info("Updating mapping on ES")
        res = self.client.indices.put_mapping(index=self.index_name, body=new_mapping)
        if res != {'acknowledged': True}:
            raise MappingUpdateError(f"Error updating mapping: {res}")

        return res

    def check_alias(self):
        assert self.use_alias
        if not self.client.indices.exists_alias(self.index_name):
            raise AliasNotFound(self.index_name)

    def check(self):
        if self.use_alias:
            return self.check_alias()
        dynamic_mapping_keys = [] # store the keys if dynamic=true
        # return list of keys where dynamic is 'true'
        def check_for_dynamic_key(mapping, key=None):
            if mapping.get('dynamic') and mapping.get('dynamic') == 'true' and key:
                dynamic_mapping_keys.append(key)
            if mapping.get('properties'):
                for prop in mapping.get('properties'):
                    check_for_dynamic_key(mapping.get('properties')[prop], prop)

        # check mapping hasn't changed
        map_info = self.client.indices.get_mapping(self.index_name)
        assert len(map_info) == 1, "Expected only one index mathing '{}'".format(self.index_name)
        # self.index_name could refer to an alias, but map_info will contain the actual aliased index
        _, mappings = list(map_info.items())[0]
        active_mapping = mappings["mappings"]
        model_mapping = self.doc_class._doc_type.mapping.to_dict()

        check_for_dynamic_key(model_mapping)

        diffs = jsondiff(active_mapping,model_mapping)
        clean_diffs = []
        # we can't really compare directly, it's no 100% equivalent, so need to filter out some diff there manually
        for diff in diffs:
            if diff["op"] == "add" and diff["value"] == "object":
                # type is object, in models, not in actual mappings
                continue
            if diff["op"] == "replace" and diff["path"].endswith("copy_to"):
                # no matter what we put in in the models, it ends as a list in mapping, and a string in models...
                continue
            if diff["op"] == "remove" and diff["path"].endswith("max_shingle_size"):
                # tokenizer/analyser, not rendered properly in models, always different...
                continue

            found_diff = False  # if dynamic='true' and found it's log in diffs its ignore that logs
            for mapping_key in dynamic_mapping_keys:
                if mapping_key in diff['path']:
                    found_diff = True
            if not found_diff:
                clean_diffs.append(diff)

        if clean_diffs and model_mapping['dynamic'] != 'true':
            logging.warning("Mappings not synchronized for index '{}'".format(self.index_name))
            logging.warning(pformat(clean_diffs))
            return clean_diffs
        else:
            logging.info("Mappings and models in synced for index '{}', all good".format(self.index_name))
            return None

    def flush(self, index=None):
        """
        For internal use only. Make sure all data in transaction logs are written in index.
        Operation can unecessarily put stress on the cluster (data will be written eventually...)
        (also, it doesn't really sync the data, so... don't use it...)
        """
        index = index or self.index_name
        self.client.indices.flush(index=index,wait_if_ongoing=True,force=True)

    def check_sortable(self, fields):
        """
        Check if fields are sortable (not Text, or if Text,
        look for a "field.raw" subfield or type Keyword, and replace)
        """
        def clean_field_value(fieldval):
            if fieldval.startswith("-"):
                fieldval = fieldval[1:]
            return fieldval

        for i,fieldval in enumerate(fields):
            # this a private method, high in inheritance...
            # deal with descending order notation
            fieldval = clean_field_value(fieldval)
            field = self.doc_class._ObjectBase__get_field(fieldval)
            fieldname = fieldval
            # if it's an alias, follow it
            if isinstance(field,Alias):
                elems = field.path.split(".")
                if len(elems) == 2:
                    # ok, we know how to handle that (eg. alias "project_id" => "_extra.project_id")
                    root,alias= elems
                    alias = clean_field_value(alias)
                    rootfield = self.doc_class._ObjectBase__get_field(root)
                    field = rootfield[alias]
                    fieldname = "{}.{}".format(root,alias)  # add the root (_extra) so ES can find it in the mappings
                else:
                    raise FieldNotSortable("Can't determined aliased field from {}".format(field))

            if isinstance(field,Text):
                # not sortable, but maybe there's a subfield
                try:
                    if isinstance(field.fields.raw,Keyword):
                        # restore sort desc char if any
                        op = ""
                        if fields[i].startswith("-"):
                            op = "-"
                        # replace with sortable one
                        fields[i] = "%s%s.raw" % (op,fieldname)
                        logging.debug("'%s' not sortable, but found sortable subfield '%s'" % (fieldval,fields[i]))
                    else:
                        raise AttributeError()
                except AttributeError:
                    raise FieldNotSortable("Field '%s' isn't sortable" % fields[i])


    def search(self, q_obj, index=None, scroll="2m", **kwargs):
        """
        Inject authorization information in query object "q_obj", according
        to current auth context, before returning results.
        """
        index = index or self.index_name
        auth_q = authorize_query(q_obj)
        # force ES to return the true total (https://www.elastic.co/guide/en/elasticsearch/reference/master/search-your-data.html#track-total-hits)
        auth_q = auth_q.extra(track_total_hits=True)
        # scroll/pager
        custom_auth_q = auth_q.extra(from_=0)
        if "size" in kwargs:
            size = kwargs['size'] if not kwargs.get('size') is None else self.cfg.default_size
            custom_auth_q = custom_auth_q.extra(size=size)

        response = self.client.search(body=custom_auth_q.to_dict(),index=index,scroll=None,**kwargs)
        # check if custom scroll using from/size will work, otherwise use original ES ones
        total = response["hits"]["total"]
        assert total["relation"] == "eq"  # because we use track_total_hits so we get the real total

        # if aggregations, hits is not the right value to check for result overflow,
        #  we need to sum the doc_count field in the "aggregations"
        num_doc_count = None
        try:  # if any failed we switch back to previous behavior
            if response.get("aggregations"):
                num_doc_count = 0
                for agg_name in response["aggregations"]:
                    # if no "buckets" key, it's not a term aggs, eg. max
                    for bucket in response["aggregations"][agg_name].get("buckets",[]):
                        num_doc_count += bucket["doc_count"]
        except (KeyError,TypeError) as e:
            num_doc_count = None
            logging.error("Error extracting aggregations counts, response was: {}".format(response))
            logging.exception(e)

        q_str = json.dumps(custom_auth_q.to_dict())
        if total["value"] >= self.cfg.custom_scroll_threshold:
            logging.info("Query '{}' matches too many documents ".format(q_str) + \
                         "(> {}), use ES scroll".format(self.cfg.custom_scroll_threshold))
            response = self.client.search(body=auth_q.to_dict(),index=index,scroll=scroll,**kwargs)
        # if scroll is None, it means caller explicitely asked for no scroll, see search() in manager
        # also don't produce scroll if all data is there
        elif not scroll is None and (0 < len(response["hits"]["hits"]) < total["value"] or  \
                (not num_doc_count is None and num_doc_count < total["value"])):
            # generate custom scroll info
            scroll_kwargs = {
                "q": q_str,
                "index": index,
                "kwargs": kwargs
            }
            scroll_id = self.scroller.generate("scroll_query",scroll_kwargs)
            response["_custom_scroll_id"] = scroll_id

        return response

    def _dispatch_sort_fields_for_search_latest(self, aggs_sort):
        # correspond to bucket where we need to set "order" instructions
        order_instructions = {"project_id": None, "path": None}
        if not aggs_sort:
            return order_instructions
        topop = []
        for sort_field in aggs_sort:
            # normalize, as "order" instruction always requires a dict with desc/asc order
            # ascending order, default is a string (comes from the way ES DSL builds the query)
            if isinstance(sort_field,str):
                sort = {sort_field: {"order": "asc"}}
            else:
                sort = sort_field
            field_name = list(sort.keys())[0]
            short_name = field_name.replace("_extra.","")
            full_name = "_extra.{}".format(short_name)
            if short_name == "numerical_revision":
                raise FieldNotSortable("Can't sort by 'numerical_revision' when search latest results" + \
                                       "(hint: 'numerical_revision' is always the latest...)")
            if short_name in order_instructions or full_name in order_instructions:
                # it matches a bucket, so we need to dispatch that sort as an "order" instruction
                topop.append(sort_field)
                # that's the order syntax within a bucket, _key refers to the field beeing "bucketed"
                order_instructions[short_name] = {"_key": sort[field_name]["order"]}
        for elem in topop:
            aggs_sort.remove(elem)

        return order_instructions

    def _find_num_partitions(self, q_obj, field, size, index=None):
        """
        Before performing aggregation and bucketing queries, we need
        to know how many partitions should be used to spread results
        accross different pages, in order to implement pagination.
        This method does a cardinality aggration on "field" and returns
        the number of partitions, where in each one, "size" results are
        found. (ok, that's mainly used by search_latest())
        """
        new_q = copy.deepcopy(q_obj)
        new_q.aggs.bucket(name="field_count",agg_type="cardinality",field=field)
        response = self.client.search(body=new_q.to_dict(),index=index)
        count = response["aggregations"]["field_count"]["value"]
        # always ceiling, so if count < size, we have at least one partition
        num = math.ceil(count/size)
        logging.debug("num_partitions: {} (count: {}, size: {})".format(num,count,size))
        return num

    def _flatten_aggs_search_latest_hits(self, response):
        hits = []
        projects = response["aggregations"]["groupByProject"]["buckets"]
        for project in projects:
            revisions = project["groupByRevision"]["buckets"]
            if not revisions:
                continue  # this can happen if no revision at all associated to a project
                          # while this should not happen, or should be very rare, we don't
                            # the whole process to crash because of that particular exception,
                            # so we just skip it
            # we should have only one there
            assert len(revisions) == 1, "More than one revision found: {}".format(pformat(revisions))
            revision = revisions[0]
            paths = revision["groupByPath"]["buckets"]
            for path in paths:
                latests = path["latest"]["hits"]
                # because we grouped by "path" (which is part of _id, to sum up, we grouped by
                # all fields that compose _id), we should have only one hit at path level
                assert len(latests["hits"]) == 1, "More than one hit found at path level: {}".format(pformat(latests))
                hits.append(latests["hits"][0])

        return hits

    def _flatten_aggs_list_projects_hits(self, response, per):
        # response used to be a aggregation output, it's now a collapse one,
        # adjust the format to maximize backward compat.
        hits = []
        projects = response["hits"]["hits"]
        for project in projects:
            dproj = {
                "project_id": project["fields"]["_extra.project_id"][0],
                "aggs": []
            }
            per_fields = project["inner_hits"]["per"]["hits"]["hits"]
            if not per_fields:
                continue  # this can happen if no revision at all associated to a project
                          # while this should not happen, or should be very rare, we don't
                            # the whole process to crash because of that particular exception,
                            # so we just skip it
            for field in per_fields:
                dproj["aggs"].append({
                    per: field["fields"][per][0]
                })

            hits.append(dproj)

        return hits

    def _prepare_aggs_response_with_scroll(self, response, hits, scroll_method, scroll_kwargs, num_partitions):
        # reformat response, getting rid of aggs and set new hits
        response.pop("aggregations")
        response["hits"]["hits"] = hits
        # total is the total number of docs considered in the query, without aggregations
        # it's not necessarily the total number of docs returned in the query. The problem is we can't know
        # that total until we explored all the results in aggregations (ie. all the partitions).
        # the only case where we know the total is when there's only one partition.
        # finally, the response formatter will include a scroll ID only if total > count (ES always
        # puts a scroll ID, even if not needed so there's this logic added to prevent adding scrolls for
        # nothing). So here's the rule:
        # - if more than one partition, "total" can be wrong, and can't be relied on
        # - if than one partition, we keep this approx. total to engage the scroll ID logic (total > count)
        # - only when there's only one partition we're sure about the total, so we can fix it with = count
        if num_partitions == 1:
            response["hits"]["total"] = {"value": len(hits), "relation": "eq"}
        else:
            scroll_id = self.scroller.generate(scroll_method,scroll_kwargs)
            response["_custom_scroll_id"] = scroll_id

        return response

    def search_latest(self, q_obj, index=None, scroll="2m", num_partitions=None, **kwargs):
        """
        Return files from latest revision, for each matching project.
        "num_partitions" is used to recursively call this method in case the computed
        num_partitions gives some sum_other_doc_count error
        """
        index = index or self.index_name
        auth_q = authorize_query(q_obj)
        # if size was passed, it now has to be about the project of project
        # otherwise we get some hits outside of aggs results we don't care about
        aggs_size = auth_q.to_dict().get("size",self.cfg.default_returned_results)
        auth_q = auth_q.extra(size=0)
        auth_q = auth_q.extra(track_total_hits=True)
        # find best number of partitions for that query. Partitions (page in pagination)
        # are based on project, not documents, in that search latest query
        orig_num_partitions = num_partitions
        num_partitions = num_partitions or self._find_num_partitions(auth_q,"_extra.project_id",aggs_size,index=index)
        if num_partitions == 0:
            # there's no partition at all, meaning no results
            return {"hits": {"hits": [], "total": {"value": 0}}}
        # same for sort, now applied to aggs results
        aggs_sort = auth_q.to_dict().get("sort")
        auth_q._sort = None  # remove from original query
        # and same for fields, applied to "latest" aggs, top_hits, where the actual docs are
        aggs_fields = auth_q.to_dict().get("_source")
        # we need to propagate sort field within the corresponding bucket
        # ex: if we sort by project_id, we can only do it within groupByProject
        # buckets, since that info is only available to ES at this level
        order_instructions = self._dispatch_sort_fields_for_search_latest(aggs_sort)
        # build aggs. Equivalent of:
        # select * from index group by project_id,numerical_revision,path having numerical_revision = max(numerical_revision)
        # note: auth_q gets modified in place as we build the aggregation

        # first bucket: per project
        by_project_args = dict(name="groupByProject",agg_type="terms",field="_extra.project_id",
                               include={
                                   "partition":0,
                                   "num_partitions": num_partitions,
                                },
                                size=aggs_size)
        if order_instructions["project_id"]:
            # inject sort order at bucket level
            by_project_args["order"] = order_instructions["project_id"]
        by_project = auth_q.aggs.bucket(**by_project_args)

        # then, for each project, we pick the max revision
        by_revision = by_project.bucket(
            name="groupByRevision",
            agg_type="terms",
            field="_extra.numerical_revision",
            size=1,  # only one revision, the highest one
            order={
                "_key":"desc"  # highest
            }
        )

        # then, group by path, since a path is unique within a project/version, we actually
        # request all files within it. If we don't do that, we only get one file in the aggs results
        by_path_args = dict(name="groupByPath",agg_type="terms",field="path",size=10000)  # max number of files within a project/version
        if order_instructions["path"]:
            by_path_args["order"] = order_instructions["path"]
        by_path = by_revision.bucket(**by_path_args)

        # finally, we ask for the top hits, that is, actual documents, otherwise we only get metric: latest revision
        latest_args = dict(name="latest",agg_type="top_hits")
        # rest of sort instructions are used at the end, once we have the documents
        if aggs_sort:
            latest_args["sort"] = aggs_sort
        if aggs_fields:
            latest_args["_source"] = aggs_fields
        _ = by_path.bucket(**latest_args)

        # return aggregations hits, same kind of output as search()
        logging.debug("search_latest: {}".format(json.dumps(auth_q.to_dict())))
        response = self.client.search(body=auth_q.to_dict(),index=index,**kwargs)
        # check if some docs aren't considered because of unbalanced size/partitions
        not_counted = response["aggregations"]["groupByProject"]["sum_other_doc_count"]
        if not_counted:
            # try to increase number of partitions (empirical)
            logging.warning("Found {} documents not considered in aggregation, increasing num_partitions".format(not_counted))
            if orig_num_partitions:
                logging.error("Can't increase, already did it... returning what current results anyways")
            else:
                return self.search_latest(q_obj=q_obj, index=index, scroll=scroll, num_partitions=num_partitions+1, **kwargs)

        hits = self._flatten_aggs_search_latest_hits(response)
        scroll_kwargs = {"q": auth_q.to_dict(), "index": index}  # scroll_latest() knows what to do with that
        response = self._prepare_aggs_response_with_scroll(response,hits,"scroll_latest",scroll_kwargs,num_partitions)

        return response

    def scan(self, q_obj, index=None):
        """
        Same as search() but using internal ElasticSearch scan() functionality
        """
        index = index or self.index_name
        auth_q = authorize_query(q_obj,index)
        return auth_q.scan()

    def bulk(self, docs, batch_size=DEFAULT_BATCH_SIZE, index=None, op="index", refresh=False):
        """
        Perform bulk operation "op", ("index","update","delete" or "upsert") on a list
        (or generator) of documents (dict or DSL object)
        """
        index = index or self.index_name
        assert op in ("index","update","delete","upsert"), "Unknown bulk operation '{}'".format(op)

        def gendata():
            for doc in docs:
                if not isinstance(doc,dict):
                    _id = doc.meta.id
                    doc = doc.to_dict()
                    doc["_id"] = _id
                _id = doc.pop("_id")
                action = {
                    "_index": index,
                    "_op_type": op,
                    "_id": _id,
                }
                if op in ("index",):
                    action.update(doc)
                elif op in ("upsert","update"):
                    # "upsert" isn't a known operation in ES, it correspond to "update" + flag below
                    action["_op_type"] = "update"
                    action["doc_as_upsert"] = op == 'upsert'
                    action["doc"] = doc
                yield action

        for chunk in iter_batch(gendata(),batch_size):
            logging.debug("Bulk index, batch contains {} documents".format(len(chunk)))
            bulk(self.client,chunk, refresh=refresh)

    def list_projects(self, q_obj, order="asc", per="_extra.version", index=None, scroll="2m", from_=0, **kwargs):
        index = index or self.index_name
        auth_q = authorize_query(q_obj)
        aggs_size = auth_q.to_dict().get("size",self.cfg.default_returned_results)
        auth_q = auth_q.extra(size=aggs_size)
        # using collapse query, with from: field for pagination, assuming index.max_result_window value is greater then
        # number of projects (can be adjusted as index setting)
        auth_q = auth_q.extra(collapse={
            "field": "_extra.project_id",
            "inner_hits": {
                "_source": False,
                "name": "per",
                "size": 1024,  # Max version per project (we need a hard limit for the query)
                "collapse": {
                    "field": per,
                }
            }
        })
        # sort by project ID
        auth_q = auth_q.sort({
            "_extra.project_id": order,
            "_extra.id": order,
        })
        # starting from... (scroll method will adjust need param to paginate)
        auth_q = auth_q.extra(**{"from":from_})
        # total count can be achieved with a cardinality aggregation
        auth_q.aggs.bucket("total","cardinality",field="_extra.project_id")
        logging.debug("list projects/versions: {}".format(json.dumps(auth_q.to_dict())))
        # _source: not returning content of the docs, not needed, we have the project IDs in the collapse section
        response = self.client.search(body=auth_q.to_dict(), index=index, _source=False, **kwargs)
        hits = self._flatten_aggs_list_projects_hits(response, per)
        response["hits"]["hits"] = hits
        # adjust total field so the response formatter keeps the one from aggragration (which is correct, total # of
        # projects) and not the original one (which is incorrect, total # of documents)
        response["hits"]["total"] = response["aggregations"]["total"]
        response.pop("aggregations")  # not needed anymore
        # determine if a scroll is needed: first but not having everything or subsequent call with more pages needed
        if from_ == 0 and aggs_size < response["hits"]["total"]["value"]:
            # rebuild original arguments to allowed calling list_projects() from the scrolling method
            # marshalling arguments to be stored in the scroll
            scroll_id = self.scroller.generate(
                "scroll_list_projects",
                {
                    "q": q_obj.to_dict()["query"]["query_string"]["query"],
                    "size": aggs_size,
                    "index": index,
                    "per": per,
                    "order": order,
                    "from_": from_ + aggs_size,
                }
            )
            response["_custom_scroll_id"] = scroll_id

        return response

    ###################
    # SCROLL HANDLERS #
    ###################

    def scroll_query(self, scroll_id):
        """
        Handle subsequent scroll calls after calling search() using a custom scroll
        """
        assert self.scroller, "No scroller set, can't handle scroll"
        scroll_kwargs = self.scroller.get(scroll_id)
        q = json.loads(scroll_kwargs.pop("q"))
        kwargs = scroll_kwargs.pop("kwargs",{})
        assert not q.get("size") is None, "Unable to scroll query data, no 'size' field: {}".format(q)
        assert not q.get("from") is None, "Unable to scroll query data, no 'from' field: {}".format(q)
        # next page
        q["from"] += q["size"]
        logging.debug("Scroll query (from={}, size={}): {}".format(q["from"],q["size"],q))
        response = self.client.search(body=q,**scroll_kwargs,**kwargs)
        if response["hits"]["hits"]:
            # reconstitute scroll_kwargs and update scroll info
            scroll_kwargs["q"] = json.dumps(q)
            scroll_kwargs["kwargs"] = kwargs
            self.scroller.set(scroll_id,scroll_kwargs)
            response["_custom_scroll_id"] = scroll_id

        return response

    def _scroll_aggregations(self, scroll_id, agg_field, flatten_func, extra_scroll_kwargs=None):
        assert self.scroller, "No scroller set, can't handle scroll"
        kwargs = self.scroller.get(scroll_id)
        q = kwargs["q"]
        index = kwargs["index"]
        # increment partition
        next_partition = q["aggs"][agg_field]["terms"]["include"]["partition"] + 1
        # check with max num. partition
        num_partitions = q["aggs"][agg_field]["terms"]["include"]["num_partitions"]
        if next_partition == num_partitions:
            # we reached the end, return empty results
            return {"hits": {"hits": []}}
        else:
            q["aggs"][agg_field]["terms"]["include"]["partition"] = next_partition
            # update scroll arguments for next call and store
            new_kwargs = {"q":q, "index": index}
            if extra_scroll_kwargs:
                new_kwargs.update(extra_scroll_kwargs)
            self.scroller.set(scroll_id,new_kwargs)
            logging.debug("Scrolling (partition {}): {}".format(next_partition,q))
            response = self.client.search(body=q,index=index)
            not_counted = response["aggregations"][agg_field]["sum_other_doc_count"]
            if not_counted:
                logging.warning("sum_other_doc_count {} for query {}".format(not_counted,q))
            hits = flatten_func(response)
            if not hits:
                logging.warning("Empty hits, trying next scroll")
                return self._scroll_aggregations(scroll_id,agg_field,flatten_func,extra_scroll_kwargs)
            # reformat response, getting rid of aggs and set new hits
            response.pop("aggregations")
            response["hits"]["hits"] = hits
            response["_custom_scroll_id"] = scroll_id

        return response

    def scroll_latest(self, scroll_id):
        """
        Handle subsequent scroll calls after searching latest files
        """
        return self._scroll_aggregations(scroll_id,"groupByProject",self._flatten_aggs_search_latest_hits)

    def scroll_list_projects(self, scroll_id):
        """
        Handle subsequent scroll calls after listing projects
        """
        assert self.scroller, "No scroller set, can't handle scroll"
        kwargs = self.scroller.get(scroll_id)
        per = kwargs["per"]
        query = parse_q(kwargs.pop("q"),index_name=kwargs["index"])
        query = query.extra(size=kwargs["size"])
        kwargs["q_obj"] = query
        response = self.list_projects(**kwargs)
        kwargs["from_"] += kwargs["size"]  # increment to next page
        # back to marshalled query
        kwargs["q"] = query.to_dict()["query"]["query_string"]["query"]
        kwargs.pop("q_obj")
        self.scroller.set(scroll_id, kwargs)
        response["_custom_scroll_id"] = scroll_id

        return response


# some dirty overriding of methods without caring about args/kwargs, it's a dummy client
# pylint: disable=unused-argument
class DummyClient:
    """
    Dummy low-level Elasticsearch client, used when no index/models are defined.
    This client returns fake or empty results.
    """

    class Indices:

        def get(self, *args, **kwargs):
            return {}
        def get_mapping(self, *args, **kwargs):
            return {"dummy.index": {"mappings": {"dynamic": 'true'}}}
        def get_field_mapping(self, *args, **kwargs):
            return {"dummy.index": {"mappings": {}}}

    def __init__(self, *args, **kwargs):
        self.indices = self.Indices()

    def get(self, *args, **kwargs):
        raise NotFoundError("Document does not exist")

    def count(self, *args, **kwargs):
        return {"count": 0}

    def search(self, *args, **kwargs):
        return {
            'took': 0,
            'hits': {
                'total': {
                    'value': 0,
                    'relation': 'eq'
                },
                'hits': []
            }
        }


