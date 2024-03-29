# pylint: disable=no-member  # self.permissions_manager injected during build()
# pylint: disable=unused-argument  # pass docs for potential usage in other scenario
# pylint: disable=redefined-outer-name)  # permissions as module + arg, fine
import logging
import os
import re
import json
from datetime import datetime

import jsondiff
import dateparser

from artifactdb.identifiers.aid import parse_key, pack_id
from artifactdb.db.elastic import TransportError
from artifactdb.backend.utils import generate_jsondiff_folder_key
from artifactdb.backend.components import plugins
from artifactdb.backend.components import sequences
from artifactdb.backend.components import storages
from artifactdb.backend.components import indexers
from artifactdb.backend.components import permissions
from artifactdb.backend.components import revisions
from artifactdb.backend.components import schemas
from artifactdb.backend.components import locks
from artifactdb.backend.components import inventories
from artifactdb.backend.components import queues
from artifactdb.backend.components import tasks
from artifactdb.backend.components import inspectors
from artifactdb.backend.managers.base import BackendManagerBase
from artifactdb.backend.managers import BulkIndexException


class ArtifactDBBackendManagerBase(BackendManagerBase):

    COMPONENTS = [
        # must always be there for an ArtifactDB API
        {"module": storages, "required": True},
        {"module": indexers, "required": True},
        {"module": permissions, "required": True},
        {"module": revisions, "required": True},
        {"module": schemas, "required": True},
        {"module": locks, "required": True},
        {"module": queues, "required": True},
        # Recommended but optionals
        {"module": sequences, "required": False},
        {"module": inventories, "required": False},
        {"module": tasks, "required": True},
        {"module": plugins, "required": False},
        {"module": inspectors, "required": False},
    ]

    @property
    def s3(self):
        """
        Backward-compatible attribute, defaulting to first storage if no storage context is
        defined.
        """
        return self.storage_manager.get_storage()

    def index_project(self, project_id, version=None, revision=None, permissions=None, skip_on_failure=False,
                      transient=None):
        """Concurrent-safe version of do_index_project, making only one project indexing is happening at a time"""
        # lock the whole project so no one can change it while we operate
        # aquire the lock *before* the try/finally, because it's already locked, we don't want to
        # release it by mistake
        self.lock_manager.lock(project_id,stage="indexing",info={"version": version, "revision": revision})
        permissions = permissions if permissions else {}
        try:
            return self.do_index_project(project_id=project_id,version=version,
                                         revision=revision,permissions=permissions,
                                         skip_on_failure=skip_on_failure,transient=transient)
        finally:
            # not matter what happened, we have to release it now. It's sad.
            self.lock_manager.release(project_id,force=True)

    def index_docs(self, project_id, version, docs, skip_on_failure=False, refresh="wait_for"):
        """
        Index given documents, using bulk upserts. Underlying
        Elastic client is selected according to the $schema version
        found in documents. Batches are prepared using all given "docs"
        and then are processed (bulk upserts) at the end.
        """

        errs = []
        def push_err(e):
            errs.append({
                "error": str(e),
                "project_id": project_id,
                "version": version,
            })

        bulk_per_clients = {}
        for doc in docs:
            esdoc = None
            es_client = None
            # deal with different schema versions according to what's found in the document
            es_client = self.es.get_client_for_document(doc)
            esdoc = es_client.doc_class()
            esdoc.init_from(**doc)
            esdoc.set_gprn(self.cfg.gprn)
            logging.info("Preparing indexing id=%s [index=%s,doc_class=%s]",
                         esdoc._id,es_client.index_name,es_client.doc_class)
            bulk_per_clients.setdefault(es_client,[]).append(esdoc)
        for client,cldocs in bulk_per_clients.items():
            try:
                logging.info("Client {}, indexing {} documents".format(client,len(cldocs)))
                client.bulk(cldocs,op="upsert", refresh=refresh)  # this will save existing fields from previous version
                                               # not set in these docs
            except TransportError as e:
                # bulk op is too big? (ADB-147)
                if e.status_code == 413:  # "Payload Too Large"
                    logging.info(f"Bulk operation too large {e.error}, indexing document one by one")
                    client.index(cldocs)  # one by one
                else:
                    push_err(e)

            except Exception as e:  # pylint: disable=broad-except  # we want to know what happened, whatever the reason
                logging.exception("Unable to index some documents: {}".format(repr(e)[:1000]))
                push_err(e)


        if not skip_on_failure and errs:
            # delete the partially indexed project/version documents
            self.delete_partially_indexed(project_id,version)
            ex = BulkIndexException(errs)
            raise ex

    def do_index_project(self, project_id, version, revision, permissions, skip_on_failure, transient=None):
        """
        Index files for given project_id (all available projects if None). If project_id
        is specified, "version" can be specified to select a specific version. "revision" can be
        passed to store an alias associated to this version.
        """
        if not revision is None:
            assert not version is None, "'revision' requires 'version' to be set"

        indexed = 0
        if version is None:
            # list all versions and call again
            for one_version in self.list_versions(project_id):
                indexed += self.do_index_project(project_id,one_version,
                                              revision=revision,permissions=permissions,
                                              skip_on_failure=skip_on_failure,
                                              transient=transient)
            return indexed


        if revision is None:
            # we might in a full re-index scenario, where revision isn't explicitely specified
            # as it has been before, during the first indexing. There should/might be a revision
            # file stored that we could use
            jrev = self.s3.get_revision(project_id,version)
            if jrev:
                revision = jrev["revision"]  # as a string, not numerical revision
            else:
                logging.warning("No previously stored revision found for {}/{}".format(project_id,version))

        self.inspectors_manager.inspect(project_id,version)
        docs = self.get_documents(project_id,version)
        self.set_schema_name(docs)
        self.set_transient(docs,project_id,version,transient)
        self.enrich_documents(docs,project_id,version) #,revision)
        self.apply_revision(docs,project_id,version,revision)
        self.apply_permissions(docs,project_id,version,permissions)
        self.apply_jsondiff(docs,project_id,version)
        # ready to go!
        self.index_docs(project_id,version,docs,skip_on_failure=skip_on_failure)
        indexed += len(docs)

        return indexed

    def set_transient(self, docs, project_id, version, transient):
        if transient:
            transient_dt = dateparser.parse(transient["expires_in"]).astimezone()
            assert transient_dt, "Couldn't parse expires_in {}".format(repr(transient))
            transient = {"expires_job_id": transient["expires_job_id"], "expires_in": transient_dt}
        for doc in docs:
            # we can't delete a field (Lucene's fault), but if a transient field becomes non-transient,
            # then we need to remove that info
            doc["_extra"]["transient"] = transient

    def set_document_revision(self, doc, revision):
        doc["_extra"]["revision"] = str(revision)
        doc["_extra"]["numerical_revision"] = int(revision)

    def create_revision(self, docs, project_id, version, revision):
        # convert to revision object
        rev = self.revision_manager.create_revision(revision)
        return rev

    def apply_revision(self, docs, project_id, version, revision):
        if revision is None:
            return
        rev = self.create_revision(docs,project_id,version,revision)
        for doc in docs:
            self.set_document_revision(doc,rev)
        # while setting the revision inside docs, we want to make sure
        # it's persistent in s3 so if we re-index projects from scratch,
        # we known what revision was associated to the version
        self.s3.register_revision(project_id,version,revision_obj=rev)

        return rev

    def enrich_documents(self, docs, project_id, version):
        """
        Hook to enrich documents (in-place) with custom information
        """

    def upload_jsondiff(self, jdiffs, project_id, version):
        """
        Stores JSON diff files, where jdiffs is dict(key=s3_key,value=json_string)
        """
        jsondiff_folder = generate_jsondiff_folder_key(project_id,version)
        for key,jdiff in jdiffs.items():
            data = json.dumps(jdiff,indent=2).encode()
            jdiff_path = os.path.join(jsondiff_folder,key)
            logging.info("Storing jsondiff data for {}".format(jdiff_path))
            self.s3.upload(jdiff_path,data)

    def apply_jsondiff(self, docs, project_id, version=None):
        if version is None:
            return  # we're doing something at project-level, jsondiff are applied
                    # at file level, so we skip that call
        jsondiff_folder = generate_jsondiff_folder_key(project_id,version)
        jsondiffs = self.s3.list_jsondiff_files(project_id,version)
        # patch docs if "_extra.metapath" field matches jsondiff path without "diff"
        for jdiff in jsondiffs:
            # jdiff: full path for jsondiff file, including project_id, version, etc...
            # get rid of jsondiff folder path, we "reason" from the project/version folder
            jdiffpath = jdiff.replace(jsondiff_folder,"")  # relative path within project/version folder
            jpath = re.sub(r"\.jsondiff$","",jdiffpath)  # may match _extra.metapath (same except .jsondiff extension)
            pat = re.escape(jpath)  # escaped string so we can regex search
            for idx,doc in enumerate(docs):
                metapath = doc["_extra"]["metapath"]
                # sometimes metapath includes starting slash
                res = re.match(r"(\/?)({})$".format(pat),metapath)
                if res:
                    assert res.groups()[1] == jpath
                    docs[idx] = self.patch_document(doc,jdiff)
                else:
                    # jdiff path doesn't match current doc, patch isn't for that document
                    logging.debug("Patch {} doesn't match doc metapath {}, skipping".format(jdiff,doc["_extra"]["metapath"]))
                    continue

    def patch_document(self, doc, patch_key):
        logging.info("Patching document {} with {}".format(doc["_extra"]["metapath"],patch_key))
        patch,_ = self.s3.download(patch_key)
        jpatch = json.loads(patch)
        new_doc = jsondiff.patch(doc,jpatch)

        return new_doc

    def enrich_with_value(self, docs, doc_key, value):
        for doc in docs:
            doc[doc_key] = value

    def enrich_with_dict(self, docs, doc_key, per_versions, skip_empty=True):
        """
        Enrich documents (in place) using per_versions dict. This
        dict is indexed by versions, doc_key is used to replace/add
        content in each doc with matching data using doc["version"]
        """
        # enrich with revision name (if any)
        for doc in docs:
            value = per_versions.get(doc["version"])
            # skip empty value by default, we don't want to store unnecessary data in index
            if not value and skip_empty:
                continue
            doc[doc_key] = value

    def set_schema_name(self, docs):
        for doc in docs:
            if doc.get("$schema"):
                schema_name,schema_version = doc["$schema"].split("/")
                schema = self.schema_manager.get_schema(schema_name,schema_version)
                if schema:
                    assert "title" in schema, "No 'title' found in schema {}".format(doc["$schema"])
                    doc_type = schema["title"].lower()
                    doc["_extra"]["type"] = doc_type
                else:
                    doc["_extra"]["type"] =  doc.get("$schema","").split("/")[0]

    def create_simple_link_document(self, project_id, version, source, dtarget):
        assert dtarget["type"] == "artifactdb"
        # intentionally without a schema nor version, so the routing decision is left to the config
        doc = {
            "path": source,
            "_extra": {
                "project_id": project_id,
                "version": version,
                "link": {
                    "artifactdb": dtarget["id"],
                }
            }
        }

        return doc

    def fix_orphan_links(self, project_id, links):
        for version in links:
            for source in links[version]:
                dtarget = links[version][source]
                logging.debug(f"Fix orphan link by creating simple_link document, {source} => {dtarget}")
                yield self.create_simple_link_document(project_id,version,source,dtarget)


    def apply_redirections(self, docs):
        """
        Extract redirections information, similar to internal metadata links, but originating
        as metadata documents. A redirection&, if pointing to a same internal metadata link, has
        precedence over the internal link. (so if A points to B in ..meta/links.json, and A points
        to C in a redirection document, A will point to C in the end).
        """
        # hard-coded redirection schema for now, with explicit version check
        redirs = [doc for doc in docs if not doc.get("$schema") is None and doc["$schema"].startswith("redirection/v3.json")]
        for redir in redirs:
            # for now, only support one target, "local"
            assert len(redir["redirection"]["targets"]) == 1
            target = redir["redirection"]["targets"][0]
            assert target["type"] == "local"  # meaning it refers to a file local to the project/version
            # we'll convert this into an artifactdb link to be compatible with the current
            # link resolution machinery (eg. self.es.fetch_by_id(...,follow_link=True))
            pid = redir["_extra"]["project_id"]
            ver = redir["_extra"]["version"]
            path = redir["path"]
            loc = target["location"]
            _tgtid = pack_id({
                "project_id": pid,
                "version": ver,
                "path": loc,
            })
            if redir["_extra"].get("link"):
                current_link = redir["_extra"]["link"]["artifactdb"]
                logging.warning(f"In {pid}/{ver}, {path} is already found as an internal link ({current_link}), " + \
                                f"it will be replaced by redirection link {_tgtid}")
            redir["_extra"]["link"] = {"artifactdb": _tgtid}

    def exclude_matching_ignored(self, meta_files, ignored):
        for meta_file in meta_files:
            if not meta_file in ignored:
                yield meta_file
            else:
                ignored.remove(meta_file)
        if ignored:
            logging.warning(f"Remaining ignored files found after filtering: {ignored}")

    def get_documents(self, project_id, version=None):
        files = self.s3.list_metadata_files(project_id,version)
        ignored = self.s3.get_ignore_list(project_id,version)
        if ignored:
            files = self.exclude_matching_ignored(files, ignored)
        links = {}  # per-versions, then per-path
        docs = []
        for key in files:

            ids = parse_key(key)

            # load link info, if any
            if not ids["version"] in links:
                meta_links = self.s3.get_links(project_id,ids["version"])
                if meta_links:
                    logging.debug(f"Found links in version {ids['version']}: {meta_links}")
                    links[ids["version"]] = meta_links

            if version:
                if ids["version"] != version:
                    continue

            doc = self.get_document(key,links)
            docs.append(doc)

        if links:
            logging.warning(f"Remaining links (orphans, no source files): {links}")
            if self.cfg.es.fix_orphan_links:
                linked_docs = self.fix_orphan_links(project_id,links)
                docs.extend(linked_docs)

        # extract redirection docs and convert them to links
        self.apply_redirections(docs)

        return docs

    def get_document(self, key, links=None):
        """
        Fetch the corresponding document from S3  and prepare it
        for indexing format (_extra field, mostly).

        "links" is a dict containing linking information so
        _extra.link can be generated accordingly. Note: links are
        stored at version-level info, that's why they must be provided along
        the "key", which is file-level (ok, we could fetch the links
        from key but would do so for all files, not efficient).
        """
        links = links or {}
        doc,headers = self.s3.load_data(key,include_headers=True)
        assert headers
        # validating metadata doc here, before adding internal _extra field
        # (which would break validation if schema says additionalProperties: false)
        if self.cfg.schema.validate_documents:
            self.validate_document(doc)
        ids = parse_key(key)
        doc["_extra"] = {
            "location": {
                "type": "s3",
                "s3": {
                    "bucket": self.s3.bucket_name,
                }
            }
        }
        doc["_extra"].update(ids)  # merge IDs into metadata

        # enrich metadata information
        if headers.get("LastModified") and isinstance(headers["LastModified"],datetime):
            doc["_extra"]["meta_uploaded"] = headers["LastModified"].astimezone()

        try:
            # fetch s3 metadata for underlying file
            # temp fix getting path info, until RDB-41
            path = doc.get("path",doc.get("PATH"))  # genomitory PATH is leaking there...
            assert path, "Missing 'path' or 'PATH' field"
            # is this a link? We "consume" (pop) the link info so we know if
            # we have remaining links without a source document
            link_info = links.get(ids["version"],{}).pop(path,None)
            # delete version if no links info anymore
            if not links.get(ids["version"],{}):
                links.pop(ids["version"],None)
            if link_info:
                assert link_info["type"] == "artifactdb", f"Unsupported link type {link_info['type']}"
                doc["_extra"]["link"] = {"artifactdb": link_info["id"]}
            data_key = f'{ids["project_id"]}/{ids["version"]}/{path}'
            file_meta = self.s3.head(data_key) or {}

            if not file_meta and link_info:
                # that's a link, we'll just fill some info about the link, not the target
                # otherwise we'd need to explore possibly a whole chain of links, and then,
                # what if the target changes? metadata there in the link wouldn't be valid
                # anymore. It's like a symlink on Linux...
                file_meta = {"LastModified": datetime.now(), "ContentLength": None}
            if file_meta.get("LastModified") and isinstance(file_meta["LastModified"],datetime):
                doc["_extra"]["uploaded"] = file_meta["LastModified"].astimezone()
            doc["_extra"]["file_size"] = file_meta.get("ContentLength")
        except (KeyError, AttributeError) as e:
            logging.exception("Can't fetch headers information for underlying file referenced by '{}': {}".format(key,e))

        return doc

    def list_projects(self):
        return self.s3.list_projects()

    def list_versions(self, project_id):
        return self.s3.list_versions(project_id)

    def download_metadata_files(self, root_dir, project_id):
        files = self.s3.list_metadata_files(project_id)
        for key in files:
            dirname, filename = os.path.split(key)
            dest_dir = os.path.join(root_dir,dirname)
            dest_file = os.path.join(dest_dir,filename)
            if not os.path.exists(dest_dir):
                os.makedirs(dest_dir)
            content = self.s3.download(key)
            with open(dest_file,"w") as fout:
                logging.info("Downloading %s", dest_file)
                fout.write(content)

    def available(self, project_id):
        """
        Check if any tasks are running for project_id. If so,
        backend isn't available (potential concurrency issues may
        happen, like determining the next revision) and an BackendNotAvailable
        error is raised.
        """
