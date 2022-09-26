# pylint: disable=missing-timeout,invalid-name,redefined-outer-name,unused-argument,unused-import
import io
from time import sleep, time
import copy
import json

import requests
import yaml
from jose import jwt

from artifactdb.utils.misc import process_coroutine
from artifactdb.tools.admin import clean_internal_metadata, wait_for_job_completion


def index_project(manager, pid, versions):
    total = 0
    for version in versions:
        total += manager.index_project(pid,version=version["version"],
                                       revision=version.get("revision"))
    return total


def sign_payload(cfg, payload):
    assert "dink" in cfg.auth.oidc.kids, "Expected 'dink' kid in config to run tests"
    dink = cfg.auth.oidc.kids["dink"]
    return jwt.encode(payload,dink["secret"],algorithm=dink["alg"], headers={'kid': 'dink'})


def generate_user_token(cfg, unixID, roles=None, ttl=None, **payload):
    user_payload = yaml.load(open("./tests/user_token_payload_tpl.yaml"),Loader=yaml.Loader)
    user_payload.update(payload)
    user_payload["preferred_username"] = unixID
    exp = time() + ttl if ttl else time() + 10
    user_payload["exp"] = exp
    if roles:
        user_payload["resource_access"] = {cfg.auth.oidc.client_id : {"roles": []}}
        for role in roles:
            user_payload["resource_access"][cfg.auth.oidc.client_id]["roles"].append(role)
    return sign_payload(cfg,user_payload)


def set_project_permissions(client, pid, permissions, expected_status="SUCCESS", wait_retry=20, wait_delay=0.5):
    url = "/projects/{}/permissions".format(pid)
    response = client.put(url,json=permissions)
    assert response.status_code == 202, "response {}: {}".format(response.status_code,response.text)
    status = wait_for_job_completion(client,response.json()["job_id"], retry=wait_retry, delay=wait_delay)
    assert status == expected_status, "Job completion status: {} job_id {}".format(status,response.json()["job_id"])
    sleep(2.)
    return response.json()["job_id"]


def expect_response(client, url, status_code, check_func=None, method="GET",json=None,headers=None):
    headers = {} if headers is None else headers
    response = getattr(client,method.lower())(url,json=json,headers=headers)
    assert response.status_code == status_code, "response.status_code: {} {}".format(response.status_code,response.text)
    if check_func:
        res_check = check_func(response)
        assert res_check, "check_func returned: {}, response was: {}".format(res_check,response.text)
    return response


def upload_files(manager, upload_contract_result, files, json_content, sleep_before_complete=0.):
    for filename in files["filenames"]:
        if filename.endswith(".json"):
            buf = io.StringIO(json.dumps(json_content[filename]))
        else:
            buf = io.StringIO(filename)  # content is the actual filename
        presigned_url = upload_contract_result["presigned_urls"][filename]
        res = requests.put(presigned_url,data=buf)
        assert res.status_code == 200, res.text

    sleep(sleep_before_complete)


def upload_and_complete(client, manager, project_id, version, files, sleep_before_complete=0):
    # enrich with json files so indexing can happen
    filenames = copy.deepcopy(files["filenames"])
    json_content = {}
    for func in files["filenames"]:
        jsonfn = "{}.json".format(func)
        filenames.append(jsonfn)
        json_content[jsonfn] = {"path":func}
    files["filenames"] = filenames

    upload_response = client.post(f"/projects/{project_id}/version/{version}/upload", json=files)
    assert upload_response.status_code == 200, "Not 200: %s" % upload_response.text
    result = upload_response.json()
    try:
        upload_files(manager,result,files,json_content,sleep_before_complete)
    except Exception:
        # clean
        manager.s3.delete_project(project_id,version)
        raise
    complete_response = client.put(result["completion_url"])
    status = wait_for_job_completion(client,complete_response.json()["job_id"])
    assert status == "SUCCESS", status

    return upload_response,complete_response

