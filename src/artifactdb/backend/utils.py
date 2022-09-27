from celery.result import GroupResult, AsyncResult

# within S3 a folder, name of the folder containing metadata
# about a project or version. Must be "internal" name
META_FOLDER = "..meta"

# same as META_FOLDER, but stores info about json diff for
# individual files
JSONDIFF_FOLDER = "..diff"

# within s3 a file that contain projects information that need to delete
DELETEME_FILE_NAME = "..deleteme"

def generate_file_key_for(project_id, version, key_name):
    project_id = project_id.rstrip("/")
    version = version.rstrip("/")
    key = f"{project_id}/{version}/{META_FOLDER}/{key_name}.json"
    return key


def generate_revision_file_key(project_id, version):
    return generate_file_key_for(project_id,version,"revision")


class ArtifactLinks(dict):
    def to_dict(self):
        return self


def generate_links_file_key(project_id, version):
    return generate_file_key_for(project_id,version,"links")


def generate_permissions_file_key(project_id=None, version=None):
    if project_id is None:
        assert version is None
        key = "{}/permissions.json".format(META_FOLDER)
    else:
        project_id = project_id.rstrip("/")
        if version:
            version = version.rstrip("/")
            key = "{}/{}/{}/permissions.json".format(project_id,version,META_FOLDER)
        else:
            key = "{}/{}/permissions.json".format(project_id,META_FOLDER)
    return key


def generate_jsondiff_folder_key(project_id, version):
    assert project_id, "jsondiff files not allowed at root level"
    assert version, "jsondiff files not allowed at project level"
    project_id = project_id.rstrip("/")
    version = version.rstrip("/")
    key = "{}/{}/{}/".format(project_id,version,JSONDIFF_FOLDER)
    return key


class DeleteMe(dict):
    def to_dict(self):
        return self


def generate_deleteme_file_key(project_id, version=None):
    project_id = project_id.rstrip("/")
    if version:
        version = version.rstrip("/")
        key = "{}/{}/{}".format(project_id,version,DELETEME_FILE_NAME)
    else:
        key = "{}/{}".format(project_id,DELETEME_FILE_NAME)
    return key


def serialize_job_result(result, deep=False):
    meta = result._get_task_meta()
    if not meta.get("children"):
        # assuming it's all serializable
        return meta
    for idx in range(len(meta["children"])):
        child = meta["children"][idx]
        if isinstance(child,GroupResult):
            # in that case, "result" in just a cryptic list of children task ID,
            # remove it as we'll get more info below
            meta.pop("result",None)
            gr_meta = {"group_id": child.id, "children": []}
            for gr_child in child.children:
                if deep:
                    gr_meta["children"].append(serialize_job_result(gr_child))
                else:
                    gr_meta["children"].append({"task_id": gr_child.id,"status": gr_child.status})
            meta["children"][idx] = gr_meta
        elif isinstance(child,AsyncResult):
            if deep:
                meta["children"][idx] = serialize_job_result(child)
            else:
                meta["children"][idx] = {"task_id": child.id,"status": child.status}

    return meta

