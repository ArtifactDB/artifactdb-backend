# pylint: disable=unused-import,broad-except,missing-timeout,
"""
Set of functions and helpers to deal with administration procedures
"""


import logging
import copy
from multiprocessing.pool import ThreadPool

import requests
import elasticsearch.helpers
from elasticsearch import Elasticsearch

# TODO; wip refactoring
from gpapy.rest.auth import god, guest
from gpapy.db.elastic.alias import update_es_aliases, move_es_alias

from artifactdb.utils.context import auth_user_context
from artifactdb.utils.misc import process_coroutine
from artifactdb.config.elasticsearch import ElasticsearchConfig




def update_es_mapping(client, skip_forbidden_op=False):
    client.update_mapping(skip_forbidden_op=skip_forbidden_op,ask=True)


def set_numerical_revision(manager, pool_size=10,  batch_size=500):
    """
    Migration from 2.0 to 2.1: revisions stored on S3
    """
    errors = []
    pids = {}  # stores revision per pid/version
    def set_revision(docs):

        for doc in docs:
            try:
                revision = doc["_extra"]["revision"]
                rev_obj = manager.revision_manager.create_revision(revision)
                doc["_extra"]["numerical_revision"] = int(rev_obj)
                pids[(doc["_extra"]["project_id"],doc["_extra"]["version"])] = revision
                yield doc
            except Exception as exc:
                logging.exception("Error for id {}: {}".format(doc.meta.id,exc))
                errors.append(doc.meta.id)
                continue

    ctx = auth_user_context.set(god)
    try:
        for model_version in manager.es.clients:
            print("Extraction documents from {}".format(model_version))
            client = manager.es.clients[model_version]
            docs = client.scan("*")
            gen = set_revision(docs)
            client.bulk(gen,op="update",batch_size=batch_size)
    except Exception as exc:
        logging.exception(exc)
        return exc
    finally:
        auth_user_context.reset(ctx)


    #import pickle
    #pickle.dump(pids,open("/tmp/pids","wb"))
    print("Stores revision as internal metadata on s3, using {} processes".format(pool_size))
    pool = ThreadPool(pool_size)

    def get_args():
        def rev(revision):
            return manager.revision_manager.create_revision(revision)
        for pid,version in pids:
            rev_obj = rev(pids[(pid,version)])
            yield (pid,version,rev_obj)
    def do_func(args):
        manager.s3.register_revision(*args)

    pool.map(do_func,get_args())

    return {"errors": errors, "pids": pids}


def store_permissions(manager, pids=None, pool_size=10):
    """
    Migration from 2.0 to 2.1: permissions stored on S3
    """

    errors = []
    def register_permissions(pid, hits):

        project_perm = {}
        for hit in hits:
            doc = hit["_source"]
            assert doc["_extra"]["project_id"] == pid
            doc_perm = {
                "owners": doc["_extra"].get("owners"),
                "viewers": doc["_extra"].get("collaborators"),
                "scope": "project",
            }
            for field in ("owners","viewers"):
                if not doc_perm[field]:
                    doc_perm.pop(field)
            if not project_perm:
                project_perm = copy.deepcopy(doc_perm)
                continue
            if project_perm != doc_perm:
                errors.append("Project {}: perrmissions differ".format(pid))
                raise Exception("Permissions differ within a project: project_perm=%s != doc_perm=%s" % (project_perm,doc_perm))
        assert project_perm and project_perm != {"scope": "project"}, project_perm
        manager.permissions_manager.register_permissions(pid,None,project_perm)

    main_ctx = auth_user_context.set(god)
    try:
        # get list of all projects
        if pids:
            print("Project IDS passed: {}".format(pids))
        else:
            print("Listing all projects")
            aggs = manager.es.aggregate("*","terms","_extra.project_id","projects",agg_size="all")
            pids = [bucket["key"] for bucket in aggs["aggregations"]["projects"]["buckets"]]
            print("Found {}".format(len(pids)))

        logging.info("Store permissions as internal metadata on s3, using {} processes".format(pool_size))
        pool = ThreadPool(pool_size)

        def do_func(pid):
            ctx = auth_user_context.set(god)  # ctx is lost in thread, re-create it
            try:
                print("Processing project {}".format(pid))
                latest = manager.es.find_latest_revision(pid)
                if not latest:
                    msg = "Project {}: no latest revision found".format(pid)
                    print(msg)
                    errors.append(msg)
                    return
                rev = {"_extra.numerical_revision": latest}
                docs = manager.es.search_by(project_id=pid,_={"scroll":None},**rev)
                register_permissions(pid, docs["hits"]["hits"])
            finally:
                auth_user_context.reset(ctx)

        pool.map(do_func,iter(pids))

    except Exception as exc:
        logging.exception(exc)
        return exc
    finally:
        auth_user_context.reset(main_ctx)

    return {"errors": errors, "pids": pids}


def clean_read_only_cluster(mgr):
    return requests.put(mgr.es.es_client.cfg.uri + "/_all/_settings",json={"index.blocks.read_only_allow_delete": None}).json()


def compare_indices(es_client_cfg, index_name1, index_name2, extract_func=None):
    """
    Compare index_name1 with index_name2. `es_client_cfg` is
    typically `mgr.es.es_client.cfg`. Compare _id by default, using
    `extract_func` which returns document's elements to compare.
    Extracted data is added to set so it must hashable.
    """
    assert index_name1
    assert index_name2
    assert isinstance(es_client_cfg,ElasticsearchConfig), "es_client_cfg: wrong type"
    client = Elasticsearch(es_client_cfg.uri)

    results = {
        "index_name1": index_name1,
        "index_name2": index_name2,
        "only_in_index_name1": None,
        "only_in_index_name2": None,
        "data_from_index_name1": None,
        "data_from_index_name2": None,
    }

    if not extract_func:
        def extract_func(doc):
            return doc["_id"]

    for i,index_name in enumerate([index_name1,index_name2]):
        docs = set()
        print(f"Extracting from {index_name}... ",end="",flush=True)
        for doc in elasticsearch.helpers.scan(client,index=index_name):
            docs.add(extract_func(doc))
        print(f"{len(docs)} document(s)")
        results[f"data_from_index_name{i+1}"] = docs

    results["only_in_index_name1"] = results["data_from_index_name1"].difference(results["data_from_index_name2"])
    results["only_in_index_name2"] = results["data_from_index_name2"].difference(results["data_from_index_name1"])

    return results
