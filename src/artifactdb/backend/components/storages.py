import json
import os
import logging
from functools import partial
from datetime import datetime, timedelta, time

import mimetypes
import magic
import yaml
import boto3
from botocore.exceptions import ClientError

from artifactdb.backend.components import BackendComponent
from artifactdb.identifiers.aid import unpack_id, generate_key
from artifactdb.identifiers.gprn import parse_resource_id, validate, NoSuchGPRN
from artifactdb.utils.context import storage_default_client_context
from artifactdb.backend.utils import META_FOLDER, generate_revision_file_key, generate_permissions_file_key, \
                                  generate_jsondiff_folder_key, generate_deleteme_file_key, generate_links_file_key, \
                                  DeleteMe, ArtifactLinks,DELETEME_FILE_NAME


class InvalidLinkError(Exception): pass
class PendingDeletionProjectError(Exception): pass
class S3ObjectNotFound(Exception): pass


class StorageManager(BackendComponent):

    NAME = "storage_manager"
    FEATURES = ["storage",]
    DEPENDS_ON = []

    def __init__(self, manager, cfg):
        self.cfg = cfg.storage
        self.clients = {}
        self.default_client = None
        self.active_client = None
        self._context = None

    def create_s3_storage(self, cfg):
        return S3Client(cfg.s3)

    def component_init(self):
        for i,cfg in enumerate(self.cfg.clients):
            creator = getattr(self,f"create_{cfg.type}_storage")
            assert not cfg.alias in self.clients, f"Storage with alias {cfg.alias} already registered"
            client = creator(cfg)
            self.clients[cfg.alias] = client
            if i == 0:
                self.default_client = client

    def get_storage(self):
        """
        Return storage client matching storage context (from config switch),
        or default client if no particular context is set.
        """
        alias = storage_default_client_context.get()
        if alias:
            client = self.clients[alias]
        else:
            client = self.default_client
        if not client is self.active_client:
            logging.debug(f"Active storage: {client}")
            self.active_client = client

        return self.active_client

    def switch(self, alias):
        if self._context:
            storage_default_client_context.reset(self._context)
            self._context = None
        if not alias is None:
            self._context = storage_default_client_context.set(alias)


class S3Client:

    def __init__(self, s3_cfg):
        params = dict(
            aws_access_key_id=s3_cfg.credentials.access_key,
            aws_secret_access_key=s3_cfg.credentials.secret_key,
        )
        if s3_cfg.endpoint:
            params["endpoint_url"] = s3_cfg.endpoint
        if s3_cfg.region:
            params["region_name"] = s3_cfg.region
        if s3_cfg.signature_version:
            params["config"] = boto3.session.Config(signature_version=s3_cfg.signature_version)
        self.client = boto3.client("s3",**params)
        self.bucket_name = s3_cfg.bucket
        self.resource = boto3.resource("s3",**params)
        self.bucket = self.resource.Bucket(self.bucket_name)
        self.cfg = s3_cfg
        self.prepare_expiration_rule()
        self.check_bucket_versioning()

    def prepare_expiration_rule(self):
        try:
            # get expiration_rule from config file
            cfg_rule = getattr(self.cfg,'expiration_rule',None)
            if cfg_rule is None:
                # should we stop here or delete present default configuration?
                logging.info("Lifecycle configuration not changed, expiration_rule not specified in config file")
                return None
            # obtain lifecycle configuration for bucket and the lifecycle rules
            lifecycle_config = self.bucket.LifecycleConfiguration()
            lifecycle_rules = []
            try:
                lifecycle_rules = lifecycle_config.rules
            except ClientError as exc:
                if exc.response.get("Error",{}).get("Code",None) in ("404","NoSuchLifecycleConfiguration"):
                    # there are no lifecycle configuration rules for this bucket
                    logging.info(f"No lifecycle configuration found for bucket: {self.bucket_name}")
                    lifecycle_rules = []
            # if we are here then we are sure we will change base rule (od delete it)
            # so we can filter out the base rule (ID = expired)
            lifecycle_rules = list(filter(lambda x: x["ID"] != "expired", lifecycle_rules))
            if cfg_rule: # add rule if config value present and set to true
                new_rule = {
                    'ID': 'expired',
                    'Expiration': {'Date': datetime.combine(datetime.now() - timedelta(days=1), time.min)}, # timestamp pointing to 'relative' yesterday
                    'Filter': {'Tag': {'Key': 'expired', 'Value': 'Y'}},
                    'Status': 'Enabled'}
                lifecycle_rules.append(new_rule)
                logging.info(f"Creating new base expiration rule: {new_rule}")
            # then we have to check if we have any rules, if yes then
            # overwrite existing ones in lifecycle config, if no then
            # log info about deleting the default one
            if lifecycle_rules:
                lifecycle_config.put(LifecycleConfiguration = {"Rules": lifecycle_rules})
                logging.info(f"Overwriting existing lifecycle rules with set of rules: {lifecycle_rules}")
            else:
                lifecycle_config.delete()
                logging.info("Deleting default lifecycle rule from s3")
        except ClientError as exc:
            msg = f"Expiration rules for s3 bucket {self.bucket_name} " + \
                  f"are inaccessible with following exception: {exc}"
            logging.warning(msg)
        return None

    def check_bucket_versioning(self):
        """
        Automatically enable or check bucket versioning according to configuration, following parameter
        `bucket_versioning`:
        - if None (default), doesn't change the current setting on the bucket
        - if True, enable versioning, regardless of current setting on the bucket
        - if False, disable versioning.
        """
        try:
            # obtain versioning for bucket
            versioning = self.bucket.Versioning()
            versioning.load()
            # check if versioning specified in config file
            if self.cfg.bucket_versioning is None:
                logging.info("Versioning not changed, bucket_versioning not specified in config file, " + \
                             f"current versioning status: {versioning.status}")
                return None
            current_status = versioning.status or "Suspended" # when versioning was never specified then versioning.status is None
            new_status = "Enabled" if self.cfg.bucket_versioning else "Suspended" # new_status is boolean
            versioning_func = {"Enabled": versioning.enable, "Suspended": versioning.suspend}
            if current_status != new_status:
                versioning_func[new_status]()
                logging.info(f"Versioning changed, current versioning status: {versioning.status}")
            else:
                logging.info(f"Versioning not changed, versioning status: {versioning.status}")
        except ClientError as exc:
            msg = f"Versioning for s3 bucket {self.bucket_name} couldn't be set to: " + \
                f"{getattr(self.cfg,'bucket_versioning',None)} with following exception: {exc}"
            logging.info(msg)

        return None

    def __str__(self):
        return f"<{self.__class__.__name__} bucket={self.bucket_name}>"

    def get_paginator(self, prefix=None, delimiter=""):
        paginator = self.client.get_paginator("list_objects")
        query = partial(paginator.paginate,Bucket=self.bucket_name,Delimiter=delimiter)
        if prefix:
            query = partial(query,Prefix=prefix)
        return query

    def list_folder(self, folder_key):
        paginator = self.get_paginator(prefix=folder_key)
        result = paginator()
        for page in result:
            for content in page.get("Contents",[]):
                yield content

    def list_projects(self, prefix=None):
        """
        Return all projects available in the bucket
        """
        paginator = self.get_paginator(prefix=prefix,delimiter="/")
        result = paginator()
        for res in result.search("CommonPrefixes"):
            if res is None:
                break
            yield res["Prefix"].rstrip("/")

    def list_versions(self, project_id):
        prefix = "{}/".format(project_id.rstrip("/"))
        paginator = self.get_paginator(prefix=prefix,delimiter="/")
        result = paginator()
        at_least_one = False
        for res in result.search("CommonPrefixes"):
            if res is None or META_FOLDER in res["Prefix"]:
                continue
            at_least_one = True
            yield res["Prefix"].rstrip("/").split("/")[-1]
        if not at_least_one:
            return []


    def list_projects_versions(self, prefix=None):
        projects = self.list_projects(prefix=prefix)
        for proj in projects:
            versions = self.list_versions(proj)
            for ver in versions:
                yield f"{proj}/{ver}"

    def list_jsondiff_files(self, project_id, version):
        # add trailing "/" to make sure we don't over match
        # Ex: without it, "GPA8" will also match "GPA85"
        jsondiff_folder = generate_jsondiff_folder_key(project_id,version)
        paginator = self.get_paginator(jsondiff_folder)

        def list_keys(expr):
            result = paginator()
            keys = []
            for res in result.search(expr):
                if res:  # could be None (???)
                    logging.debug("Found jsondiff file: %s", res["Key"])
                    keys.append(res["Key"])
            return keys

        jsondiff_keys = list_keys("Contents[?ends_with(@.Key,'.jsondiff')]")
        if jsondiff_keys:
            return jsondiff_keys
        else:
            logging.info("No jsondiff files found")
            return []

    def list_metadata_files(self, project_id=None,version=None, ignore_pending_deletion=False):
        prefix = None
        if not project_id and version:
            raise ValueError("Missing Project ID, Can not accept version without project id")

        if project_id:
            prefix = project_id
            # add trailing "/" to make sure we don't over match
            # Ex: without it, "GPA8" will also match "GPA85"
            if not project_id.endswith("/"):
                prefix = "%s/" % project_id
            if version:
                if not version.endswith("/"):
                    prefix += "%s/" % version
                else:
                    prefix += version

        paginator = self.get_paginator(prefix)

        def list_keys(expr):
            result = paginator()
            keys = []
            for res in result.search(expr):
                if res:  # could be None (???)
                    if META_FOLDER in res["Key"]:
                        logging.debug("Skip {} (internal metadata)".format(res["Key"]))
                        continue
                    logging.debug("Found metadata file: %s", res["Key"])
                    keys.append(res["Key"])
            return keys

        # JMESPath expression matching yaml OR json files
        # switching to v2, json-based metadata files only
        #expr = "Contents[?ends_with(@.Key,'.json')]"
        if not ignore_pending_deletion:
            deleteme_keys = list_keys(f"Contents[?contains(Key,'{DELETEME_FILE_NAME}')]")
            if deleteme_keys:
                raise PendingDeletionProjectError(f"Deletion in progress for project '{project_id}'")
        yaml_keys = list_keys("Contents[?ends_with(@.Key,'.yaml')]")
        json_keys = list_keys("Contents[?ends_with(@.Key,'.json')]")
        if yaml_keys and json_keys:
            logging.warning("Found YAML *and* JSON metadata files, only JSON files considered")
            return json_keys
        elif json_keys:
            return json_keys
        elif yaml_keys:
            return yaml_keys
        else:
            logging.info("No metadata files found")
            return []

    def extract_headers(self, response):
        return {
            "LastModified": response.get("LastModified"),
            "ContentLength": response.get("ContentLength"),
            "ETag": response.get("ETag"),
            "VersionId": response.get("VersionId"),
            "ContentType": response.get("ContentType"),
            "Metadata": response.get("Metadata"),
        }

    def head(self, key):
        """
        Return metadata for give key/file. If key doens't exist,
        None is returned
        """
        try:
            response = self.client.head_object(Bucket=self.bucket_name,Key=key)
            return self.extract_headers(response)
        except ClientError as exc:
            if exc.response.get("Error",{}).get("Code",None) == "404":
                return None
            else:
                # something else, more serious
                raise

    def download(self, key, binary=False):
        """
        Download file identified by an s3 key and return a file-like object
        """
        response = self.client.get_object(Bucket=self.bucket_name,Key=key)
        if binary:
            content = response["Body"].read()
        else:
            content = response["Body"].read().decode()
        headers = self.extract_headers(response)
        return content,headers

    def upload(self, key, data, content_type="binary/octet-stream"):
        if isinstance(data,str):
            data = data.encode()
        response = self.client.put_object(Bucket=self.bucket_name,Key=key,Body=data,ContentType=content_type)
        return response

    def delete(self, key):
        self.client.delete_object(Bucket=self.bucket_name,Key=key)

    def expire(self, key, dt:datetime=None):
        """
        Add "expired" tag with value "Y" to given key - so if base expiration rule is turned on
        (expiration_rule field has value true in s3 config) then the specified key will
        have expiration date set. If there is no rule, then the tag will be assigned but the key
        will not be designated to expired.
        The key must exists.
        """
        if dt:
            logging.error(f"expiration in future (dt argument given: {dt}) not implemented yet")
            raise Exception(f"expiration in future (dt argument given: {dt}) not implemented yet")
        self.add_tag(key = key, tag_key = "expired", tag_value = "Y")

    def delete_project(self, project_id, version=None):
        # make sure no trailing slash, S3 is picky about it
        project_id = project_id.strip("/")
        version = version and version.strip("/")
        prefix = "%s/" % project_id
        project_prefix = prefix
        if version:
            prefix += "%s/" % version
        logging.info("Deleting s3://%s/%s*" % (self.bucket_name,prefix))
        self.bucket.objects.filter(Prefix=prefix).delete()
        if not version is None:
            # we delete a specific version, is the project folder empty now? ie. delete it as well?
            only_meta = True
            for obj in self.bucket.objects.filter(Prefix=project_prefix):
                if not "..meta" in obj.key:
                    only_meta = False
                    break
            if only_meta:
                logging.info("Project folder empty or contains ..meta only, deleting it")
                logging.info("Deleting s3://%s/%s*" % (self.bucket_name,project_prefix))
                self.bucket.objects.filter(Prefix=project_prefix).delete()
            else:
                logging.info("Project folder not empty, not cleaning further")

    def mark_as_deleteme(self, project_id, version=None):
        deleteme_obj = DeleteMe(project_id=project_id,version=version,
                                marked_at=datetime.now().isoformat())
        self.register_internal_metadata(project_id,version,deleteme_obj,generate_deleteme_file_key)

        return deleteme_obj

    def get_internal_metadata(self, project_id, version, generate_key_func):
        key = generate_key_func(project_id,version)
        try:
            data = self.load_data(key)
            logging.info("Found internal metadata: {} => {}".format(key,repr(data)))
            return data
        except ClientError as exc:
            if exc.response.get("Error",{}).get("Code",None) in ("404","NoSuchKey"):
                return None
            else:
                # something more serious is happening there, throw the "patate chaude"
                raise

    def get_permissions(self, project_id=None, version=None):
        """
        Return version-specifc (if passed), project-specific (if passed)
        or global permissions (if project_id/version None)
        """
        return self.get_internal_metadata(project_id,version,generate_permissions_file_key)

    def get_revision(self, project_id, version):
        return self.get_internal_metadata(project_id,version,generate_revision_file_key)

    def get_links(self, project_id, version):
        """
        Extract links information stored as internal metadata (..meta/links.json)
        """

        links_info = self.get_internal_metadata(project_id,version,generate_links_file_key) or {}
        return ArtifactLinks(links_info)

    def register_internal_metadata(self, project_id, version, meta_obj, generate_key_func):
        """
        Store internal metadata (revision, permissions, etc...) information on s3,
        associated "version" with given "meta_obj", for specified "project_id".
        "meta_obj" implements to_dict(), a jsonifiable dictionary representing the
        internal metadata.
        """
        key = generate_key_func(project_id,version)
        jobj = json.dumps(meta_obj.to_dict(),indent=4)
        logging.info("Register internal metadata: {} => {}".format(key,repr(meta_obj)))
        self.bucket.put_object(Key=key,Body=jobj,ContentType="application/json")

    def delete_internal_metadata(self, project_id, version, generate_key_func):
        """
        Delete internal metadata file from S3. No question asked.
        """
        key = generate_key_func(project_id,version)
        self.delete(key)

    def clean_internal_metadata(self, project_id):
        """
        Delete all internal metadata files, recursively, from a project ID.
        Use with caution...
        """
        prefix = "{}/".format(project_id)
        paginator = self.get_paginator(prefix)
        # everything that has "..<name>" in the path (eg. ..meta, ..diff, ...)
        for meta_folder in ("..meta","..diff"):
            expr = "Contents[?contains(@.Key,'{}')]".format(meta_folder)
            for res in paginator().search(expr):
                if res:
                    self.delete(res["Key"])
            self.delete("{}/{}".format(prefix,meta_folder))

    def register_revision(self, project_id, version, revision_obj):
        self.register_internal_metadata(project_id,version,revision_obj,generate_revision_file_key)

    def register_permissions(self, project_id, version, permissions_obj):
        self.register_internal_metadata(project_id,version,permissions_obj,generate_permissions_file_key)

    def register_links(self, project_id, version, links_obj):
        self.register_internal_metadata(project_id,version,links_obj,generate_links_file_key)

    def delete_permissions(self, project_id, version):
        return self.delete_internal_metadata(project_id,version,generate_permissions_file_key)

    def delete_revision(self, project_id, version):
        return self.delete_internal_metadata(project_id,version,generate_revision_file_key)

    def delete_links(self, project_id, version):
        return self.delete_internal_metadata(project_id,version,generate_links_file_key)

    def load_yaml(self, yamldat):
        return [doc for doc in yaml.load_all(yamldat,Loader=yaml.Loader) if doc][0]

    def load_json(self, jsondat):
        return json.loads(jsondat)

    def load_data(self, key, include_headers=False):
        """
        Return documents contained in yaml file identified by "key"
        """
        dat,headers = self.download(key)
        try:
            ext = os.path.splitext(key)[-1].replace(".","")
            content = getattr(self,"load_%s" % ext)(dat)
            if include_headers:
                return (content,headers)
            else:
                return content
        except AttributeError as exc:
            raise TypeError(f"Unknown extension for key {key}: {ext} ({exc})")

    def get_presigned_url(self, key, expires_in=None):
        url = self.client.generate_presigned_url('get_object',
                Params={
                    'Bucket': self.bucket_name,
                    'Key': key},
                ExpiresIn=expires_in or self.cfg.presigned_url_expiration)
        return url

    def get_presigned_url_for_upload(self, key, expires_in=None):
        try:
            # Generate a presigned S3 POST URL
            url = self.client.generate_presigned_url(
                ClientMethod='put_object',
                Params={
                    'Bucket': self.bucket_name,
                    'Key': key,
                    },
                ExpiresIn=expires_in or self.cfg.presigned_url_expiration
            )
            return url
        except ClientError as exc:
            logging.exception(exc)
            return None

    def byte_range_query(self, key, start, end):
        obj = self.client.get_object(Bucket=self.bucket_name, Key=key, Range="bytes={}-{}".format(start,end))
        data = obj["Body"].read()
        return data

    def guess_mimetype(self, data_key):
        # guess the mimetype from the file name
        mimetype = mimetypes.guess_type(data_key)[0]
        if mimetype is None:
            # download the starting 1024 bytes of file content, so magic can guess the file mimetype
            file_data = self.byte_range_query(data_key, start=1, end=1024)
            if file_data:
                mime = magic.Magic(mime=True)
                mimetype = mime.from_buffer(file_data)
        return mimetype

    def copy_folder(self, src_key, tgt_key):
        for obj in self.bucket.objects.filter(Prefix=src_key):
            old_source = {
                'Bucket': self.bucket_name,
                'Key': obj.key
            }
            # replace the prefix
            new_key = obj.key.replace(src_key, tgt_key, 1)
            new_obj = self.bucket.Object(new_key)
            logging.debug(f"Copying {obj.key} => {new_key}")
            new_obj.copy(old_source)

    def create_link(self, source_id, target_id):
        source_ids = unpack_id(source_id)
        target_ids = unpack_id(target_id)
        if source_id == target_id:
            raise InvalidLinkError("Self-linking not allowed")
        if "latest" in (source_ids["version"].lower(),target_ids["version"].lower()):
            raise InvalidLinkError("Links using 'latest' are not allowed")
        # all links are stored in one file, load/modify/save it
        links = self.get_links(source_ids["project_id"],source_ids["version"])
        links[source_ids["path"]] = {"type": "artifactdb", "id": target_id}
        self.register_links(source_ids["project_id"],source_ids["version"],links)

    def unlink(self, source_id):
        source_ids = unpack_id(source_id)
        links = self.get_links(source_ids["project_id"],source_ids["version"])
        if not source_ids["path"] in links:
            raise InvalidLinkError(f"{source_id} is not a link")
        links.pop(source_ids["path"])
        if links:
            self.register_links(source_ids["project_id"],source_ids["version"],links)
        else:
            self.delete_links(source_ids["project_id"],source_ids["version"])

    def find_stale_projects(self):
        paginator = self.get_paginator()
        results = paginator().search("Contents[?contains(Key,'{}')]".format(DELETEME_FILE_NAME))
        return results

    def get_s3_arn(self, bucket, project_id, version=None, path=None):
        arn = f"arn:aws:s3:::{bucket}/{project_id}/"
        if path:
            assert version
            # in case path starts with "/" (this would mess the following path join)
            path = path.lstrip("/")
            arn = os.path.join(arn,version,path)
        elif version:
            arn = os.path.join(arn,version) + "/"
        return arn

    def get_s3_url(self, gprn, gprn_cfg=None, check=True):
        """
        Return s3 url for given `gprn`. If `grpn_cfg` is set, will
        perform sanity checks to ensure `gprn` is actually handled by
        the API (recommended). When `check` is False, the s3 url is
        returned even if the corresponding key doesn't exist.
        """

        def check_key_exists(key):
            files = list(self.bucket.objects.filter(Prefix=key)) if key.endswith("/") else self.head(key)
            if not files:
                raise NoSuchGPRN(f"No location found for given GPRN: {gprn}")

        bucket_name = self.bucket_name
        s3_location = None
        parsed = validate(gprn, gprn_cfg)  # validate method validate the gprn and return the parsed value
        resource_id = parse_resource_id(parsed["type-id"], parsed["resource-id"])
        if resource_id:
            if resource_id.get("path"):
                key = generate_key(resource_id)
            elif resource_id.get("version"):
                key = os.path.join(resource_id["project_id"], resource_id["version"]) + "/"
            else:
                key = resource_id["project_id"] + "/"
            check and check_key_exists(key)  # pylint: disable=expression-not-assigned
            s3_location = "s3://{}/{}".format(bucket_name, key)

        return s3_location

    def restore(self, prefix, dryrun=False):
        """
        Restore deleted data under `prefix`, removing any DeleteMarker
        from a bucket with versioning enabled
        """
        if not prefix.endswith("/"):
            prefix += "/"  # strict prefix
        # list-objects-versions, then check DeleteMarkers, and if any, delete all of them
        extra = {}  # holds params when requesting more pages
        while True:
            res = self.client.list_object_versions(Bucket=self.bucket_name,Prefix=prefix,**extra)
            delmarkers = res.get("DeleteMarkers",None)
            if not delmarkers:
                logging.info("No delete markers found, nothing to restore")
                break
            for delmarker in delmarkers:
                logging.info("{}Removing delete marker for '{}'".format(
                    dryrun and "[dry-run] " or "",
                    delmarker["Key"]))
                if not dryrun:
                    self.client.delete_object(Bucket=self.bucket_name,Key=delmarker["Key"],VersionId=delmarker["VersionId"])
            if not res["IsTruncated"]:
                break
            extra = {"KeyMarker": res["NextKeyMarker"], "VersionIdMarker": res["NextVersionIdMarker"]}

    def tag_project(self, project_id, version, tag_key, tag_value):
        dir_key = f"{project_id}/{version}"
        keys = [o['Key'] for o in self.list_folder(dir_key)]

        for key in keys:
            self.add_tag(key, tag_key, tag_value)

    def add_tag(self, key, tag_key, tag_value):
        try:
            tag_set = self.get_tags(key)
            tag_inds = [idx for idx, t in enumerate(tag_set) if t['Key'] == tag_key]
            add_obj = {'Key': tag_key, 'Value': tag_value}
            if len(tag_inds) == 0:
                tag_set.append(add_obj)
            else:
                assert len(tag_inds) == 1, "Expecting one and only one tag, got: {}".format(tag_inds)
                old_val = tag_set[tag_inds[0]]['Value']
                if old_val != tag_value:
                    tag_set[tag_inds[0]] = add_obj
                else:
                    # nothing to change
                    return
            _ = self.client.put_object_tagging(
                Bucket = self.bucket_name,
                Key = key,
                Tagging = {'TagSet': tag_set}
            )
        except self.client.exceptions.NoSuchKey:
            raise S3ObjectNotFound(f"Key: '{key}' not found in s3 bucket: '{self.bucket_name}'.")

        except self.client.exceptions.NoSuchBucket:
            raise S3ObjectNotFound(f"Bucket: '{self.bucket_name}' not found.")

    def get_tags(self, key):
        try:
            tag_resp = self.client.get_object_tagging(
                Bucket = self.bucket_name,
                Key = key
            )
            return tag_resp["TagSet"]
        except self.client.exceptions.NoSuchKey:
            raise S3ObjectNotFound(f"Key: '{key}' not found in s3 bucket: '{self.bucket_name}'.")
        except self.client.exceptions.NoSuchBucket:
            raise S3ObjectNotFound(f"Bucket: '{self.bucket_name}' not found.")


#########################
# Backend method mixins #
#########################

