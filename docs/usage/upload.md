# Upload artifacts

This section describes how to upload artifacts, ie. data and metadata files, to and ArtifactDB API. This is a multi-step
process, during which the [project](../concepts/project) enters different [states](../concepts/lifecycle).

Generally speaking, in a traditional setup, uploading artifacts involves requesting the instance to provision a project
identifiers, or a new version within an existing project. This implies the instance itself exhibits a feature called
`auto-provisioning`, handled by a component named the [sequence manager](../sequences), where provisioning and versioning
is under the control of the instance itself. There are other use cases though where this "source" of IDs and versions is
external to the instance. In that case, the sequence component is not used but instead, on the client side, the
provisioning is performed *before* starting the upload process.

## External and auto-provisioning

There are multiple REST endpoints involved in the uploading process, depending on whether the instance is using auto- or
external IDs and version provisioning.

- `POST /projects/upload` is used to ask the instance to provision both a project ID, as well as a first version.
- `POST /projects/{project_id}/upload` is used to provision a new version within an existing project. It will fail if
  that project doesn't exist.
- `POST /projects/{project_id}/version/{version}/upload`, see below the different use cases

The first two endpoints require, by default, the role `creator`, to limit, if necessary, the process of project creation
to a set of users. Upon project and/or version provisioning, the endpoint redirects to the same endpoint, the third one,
`POST /projects/{project_id}/version/{version}/upload`. This endpoint is also used with external provisioning (not
auto-provisioning), where `project_id` and `version` are provided by the client. To prevent anybody from using this
endpoint, possibly overwriting or corrupting an existing project, the role `uploader` is required in the default
authorization configuration. The role `uploader` is the context should be given with caution, as it provides, at least
for the upload process, similar power as an administrator of the instance, since it allows to change data and metadata
on any project.

That said, this last endpoint requires the role `uploader`, but going through auto-provisioning and with the first
endpoints `POST /projects/upload` and `POST /projects/{project_id}/upload`, the role `creator` is required. Yet both
these endpoints will redirect to the one requiring `uploader` permissions. How is it possible for a simple `creator` to
be able to call an endpoint reserved for `uploader`? The instance uses an internal pre-signed URL mechanism to
temporarily promote the user's role from `creator `to `uploader`, specifically and only for that request, only for the
newly provisioned project ID and/or version (the pre-signed upload URL can't be reused for other projects). 

TODO: link to "Internal pre-signed URL" section


## The uploading process

There are there main steps: preparing the upload, uploading data, and marking the upload as complete. 


### 1. Preparing the upload

The first step is instructing ArtifactDB we want to upload data. As previously seen, we can use different entry
endpoints, but overall in the end, they all converge to the same one, `/projects/{project_id}/version/{version}/upload`,
also known as the "fully qualified upload endpoint", since project ID and version are fully specified.  In other words,
the parameters and body content of the request going to that final endpoint are the same for all upload endpoints, the
other endpoints are "just" to used during auto-provisioning.

With that in mind, in the endpoint `/projects/{project_id}/version/{version}/upload`, we thus specify the `project_id`
as well as the `version` within that project. In the body of that upload request, we instruct ArtifactDB what the files
we want to upload, and when we think we wil be done uploading data:

```json
{
  "filenames": [
    "report.txt",
    "report.txt.json"
  ],
  "completed_by": "in 10 minutes"
}
```

Here, we want to upload two files, one containing some data (`report.txt`) and the other containing metadata describing
the data, as a json file (`report.txt.json`). The `report.txt` file can contain anything, let's say:

```bash This report is so amazing, wow.  ```

The actual structure of the JSON document for the metadata depends on the schema used by the ArtifactDB API, and thus is
specific to the instance. In our example, we'll use a simple schema named `compiled_report`, with the following
structure (again, this schema is just an example, it could be anything... almost):

```json
{
  "$schema": "http://json-schema.org/draft-07/schema",
  "$id": "compiled_report/v1.json",
  "type": "object",
  "title": "Compiled report",
  "description": "A HTML report generated from compilation of executable code",
  "required": [
    "source",
    "md5sum",
    "path"
  ],
  "properties": {
    "source": {
      "type": "string",
      "title": "Source report path",
      "description": "A string containing a path to the source file."
    },
    "md5sum": {
      "type": "string",
      "title": "MD5 checksum",
      "description": "A string containing the expected MD5 checksum for the compiled report."
    },
    "path": {
      "type": "string",
      "title": "Relative path",
      "description": "A string containing the path to the compiled report."
    }
  }
}
```

According that schema, we need to provide fields `source`, `md5sum` and `path`, so the `report.txt.json` could look like this:

```json
{
  "source": "report.pl",
  "path": "report.txt",
  "md5sum": "38a3b0a6d8a9b6df7165a7d10cc8a57f",
  "$schema": "compiled_report/v1.json"
}
```

> Note: in the source field, we just pretend the report is generated a from Perl script.

The `$schema` field tells the ArtifactDB API what kind of artifact is being uploaded. It internally translates into an
index in Elasticsearch (see [architecture](../architecture) for more).

With these two files ready, we can proceed to the upload. We'll pretend to upload to project `PRJ000001` for version
`1`.

In the rest of this document, we assume `$token` is an environment variable containing a JWT token containing the
necessary permissions to upload data (see section above about [permissions](upload#who-can-upload-artifacts))

```bash
$ token=eyJhbGciOiJSUzI1NiIsInR5c...
$ curl -XPOST https://myinstance.mycompany.com/projects/PRJ000001/version/1/upload \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $token" \
    --data '{"filenames": ["report.txt","report.txt.json"],"completed_by": "in 5 minutes"}'
```
```json
{
    "project_id":"PRJ000001",
    "version":"1",
    "revision":"REVISION-1",
    "presigned_urls":{
        "report.txt":"https://mybucket.s3.amazonaws.com/PRJ000001/1/report.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAVB4ETCFN2Z4X3R73%2F20201222%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20201222T183917Z&X-Amz-Expires=120&X-Amz-SignedHeaders=host&X-Amz-Signature=d2be08f767e313e8d002b54ccc2b590d6783b13cbc3438459ac3270d0e437def",
        "report.txt.json":"https://mybucket.s3.amazonaws.com/PRJ000001/1/report.txt.json?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAVB4ETCFN2Z4X3R73%2F20201222%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20201222T183917Z&X-Amz-Expires=120&X-Amz-SignedHeaders=host&X-Amz-Signature=c2626a62321d211b16cefb79a6443d4f3aea3bfe6cf3bd350ee084dcdbeb4692"
    },
    "complete_before":"2020-12-22T19:39:17.388465",
    "completion_url":"/projects/PRJ000001/version/1/complete?revision=REVISION-1&purge_job_id=7c3e2d69-d816-4965-b347-116ab9ef47ad",
    "purge_job_id":"7c3e2d69-d816-4965-b347-116ab9ef47ad",
    "expires_job_id":null
```

The response contains several important information:
- ResultsDB has assigned the `revision` **REVISION-1**. It's the first time we upload artifact for the project,
  so this is the first revision.
- a `completion_url` is provided, we'll use it during the last step.
- we said, during the POST request, we'll be done uploading files in 5 minutes, ResultsDB reports a `completion_before` data, as a reminder
  (datetimes are in UTC). Should we move past this time limit, our data would be automatically be purged (removed from s3).
- finally, and most importantly, we obtain two pre-signed URLs, for each of our report files.

At that stage, the project has entered the state `uploading` (see [lifecycle](../concepts/lifecycle)). It's not possible to upload
any other data for that project, we would obtain a lock error:

```json
{
    "status":"error"
    "reason":"Project 'PRJ000001' is locked: {'stage': 'uploading', 'info': True}"
}
```

The only way is to move forward and upload files and hit the completion URL,
or wait the completion time to expire (in our case, 5 minutes).

Let's move on the next section and upload data.


### 2. Uploading data

With the pre-signed URLs we obtain during the provisioning step, we can now upload our files. These pre-signed URLs points to
Amazon S3, the upload itself doesn't go through the API but rather directly to S3. Using this process, we can benefit from the cloud
bandwidth. Let's upload our two files. This time, there's no need for a token, these pre-signed URLs already embeds permissions.

> Note: these pre-signed URLs are only valid for a limited time, 2 minutes... They can be used multiple times during that time frame though.
> 
> Content-type for the files must be set by the client, and It can not be change after that. Example: -H "Content-Type: text/plain"

```bash
$ curl --upload-file report.txt "https://mybucket.s3.amazonaws.com/PRJ000001/1/report.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAVB4ETCFN2Z4X3R73%2F20201222%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20201222T183917Z&X-Amz-Expires=120&X-Amz-SignedHeaders=host&X-Amz-Signature=d2be08f767e313e8d002b54ccc2b590d6783b13cbc3438459ac3270d0e437def"
$ curl --upload-file report.txt.json "https://mybucket.s3.amazonaws.com/PRJ000001/1/report.txt.json?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAVB4ETCFN2Z4X3R73%2F20201222%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20201222T183917Z&X-Amz-Expires=120&X-Amz-SignedHeaders=host&X-Amz-Signature=c2626a62321d211b16cefb79a6443d4f3aea3bfe6cf3bd350ee084dcdbeb4692s"
```

Everything has been uploaded properly, we can now move the final stage.


### 3. Completing the upload

We can now inform the ArtifactDB API that we're done uploading the files and it should now proceed to their integration.
We use the `completion_url`. It's also during that time we can specify permissions for the upload. We'll set a specific owner,
and public read access, as well as scope *project*, in the body of the PUT request (refer to artifacts' [permissions](../concepts/permissions) for more):

```bash
$ curl -XPUT "https://myinstance.mycompany.com/projects/PRJ000001/version/1/complete?revision=REVISION-1&purge_job_id=de42fb43-974b-4320-afa5-574bdd33a632" \
    -d '{"owners": "lelongs", "write_access": "owners", "read_access": "public", "scope": "project"}' \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $token"
```
```json
{
    "status":"accepted",
    "job_url":"/jobs/f31a86b5-1d63-4f0c-a035-8ebd0abc684b",
    "job_id":"f31a86b5-1d63-4f0c-a035-8ebd0abc684b"
}
```

The response code is 202 (not shown here) meaning the request has been accepted, ArtifactDB is processing it in an asynchronous manner.
In return, we obtain information about that asynchronous job. We can use the `job_url` to check the progress:

> Note: there's no need to pass a token for the `/jobs` endpoints, as an randomly generated ID is required as a job ID, it's
  basically not possible to "guess" it. Also, there's no sensitive information displayed by that endpoint.

```bash
$ curl "https://myinstance.mycompany.com/jobs/f31a86b5-1d63-4f0c-a035-8ebd0abc684b"
```
```json
{
    "status":"SUCCESS",
    "result":{
        "project_id":"PRJ000001",
        "indexed_files":1
    },
    "traceback":null,
    "children":[],
    "date_done":"2020-12-22T18:56:07.962614",
    "task_id":"f31a86b5-1d63-4f0c-a035-8ebd0abc684b"
}
```

It's a `SUCCESS`, we can our project has been integrated, and one file has indexed (the metadata).

Since the project is public, we can easily retrieve metadata for instance, without any token:

```bash
$ curl "https://myinstance.mycompany.com/projects/PRJ000001/version/1/metadata"
```
```json
{
    "results":[
        {
            "source":"report.pl",
            "path":"report.txt",
            "md5sum":"38a3b0a6d8a9b6df7165a7d10cc8a57f",
            "_extra":{
                "project_id":"PRJ000001",
                "metapath":"report.txt.json",
                "version":"1",
                "meta_uploaded":"2020-12-22T18:54:53+00:00",
                "uploaded":"2020-12-22T18:54:53+00:00",
                "file_size":141,
                "revision":"REVISION-1",
                "numerical_revision":1,
                "permissions":{
                    "scope":"project",
                    "owners":[
                        "lelongs"
                    ],
                    "read_access":"public",
                    "write_access":"owners"
                },
                "type":"compiled report",
                "id":"PRJ000001:report.txt@1",
                "$schema":"compiled_report/v1.json",
                "meta_indexed":"2020-12-22T19:17:57.748477+00:00",
                "index_name":"resultsdb-prd-default-20200817"
            }
        }
    ],
    "count":1,
    "total":1
}
```

Please refer to [access](access) for more about fetch and searching data from ArtifactDB.


## Transient artifact

With `gpapy` version `0.4+`, it's possible to upload transient artifacts, which automatically get
deleted after a certain amount of time. This can be specified while hitting the `/upload` endpoint,
by specify the `expires_in` field. The format is the same as the `completed_by`, eg. `in 2 days`, or
dates like `2020-12-31 12:59:59`.

> Note: `expires_in` must happen **after** `completed_by`.

Let's try that, on the same project as before (which will result in cleaning what we did, on purpose...):

```bash
$ token=eyJhbGciOiJSUzI1NiIsInR5c...
$ curl -XPOST https://myinstance.mycompany.com/projects/PRJ000001/version/1/upload \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $token" \
    --data '{"filenames": ["report.txt","report.txt.json"],"completed_by": "in 1 minute", "expires_in": "in 2 minutes"}'
```
```json
{
    "project_id":"PRJ000001",
    "version":"1",
    "revision":"REVISION-2",
    "presigned_urls":{
        "report.txt":"https://mybucket.s3.amazonaws.com/PRJ000001/1/report.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAVB4ETCFN2Z4X3R73%2F20201222%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20201222T193126Z&X-Amz-Expires=120&X-Amz-SignedHeaders=host&X-Amz-Signature=d8fc4e7301375ac0a26617f56efbe431e1f3f58b568bf746f35b63eaeba3f924",
        "report.txt.json":"https://mybucket.s3.amazonaws.com/PRJ000001/1/report.txt.json?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAVB4ETCFN2Z4X3R73%2F20201222%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20201222T193126Z&X-Amz-Expires=120&X-Amz-SignedHeaders=host&X-Amz-Signature=2935c706ae915deaac1723d4d033c5430fe6f131894aa06d6c715662a13128da"
    },
    "complete_before":"2020-12-22T19:32:26.641375",
    "completion_url":"/projects/PRJ000001/version/1/complete?revision=REVISION-2&purge_job_id=ba40f466-347f-4c7c-9cc2-db85c92db0c2",
    "purge_job_id":"ba40f466-347f-4c7c-9cc2-db85c92db0c2",
    "expires_job_id":"34229a07-2e21-480d-9466-fcd8ff257f74"
}
```

We obtain the same kind of information as before, except we now have an `expires_job_id`. Internally, ArtifactDB
scheduled a job with this ID, which will run in 2 minutes (a little bit less now), to purge the data from the API.
Another interesting point to notice is we're uploading data on the same version `1` as before, but we get an incremented
revision number, `REVISION-2`.  ArtifactDB tracks internal revision independently from the version, see
[versioning](../concepts/version) for more.

After two long minutes, if we query again the data, we get an error:

```bash
$ curl "https://myinstance.mycompany.com/projects/PRJ000001/version/1/metadata"
```
```json
{
    "status":"error"
    "reason":"No such project/version"
}
```

As expected, the project has been removed from ArtifactDB. The files on Amazon S3 have been deleted, and the documents
from Elasticsearch have been removed as well. It's gone...

> Note: if permissions were defined with scope `project`, these permissions are kept on S3. It means if you had upload
  permissions before for that project, you still have them after the purge has occured, which means you still have
  permissions to upload a new version for that project. In other words, you still own that space...


## Linking data (deduplication)

One common scenario when uploading artifacts is metadata itself changes, eg. with additional fields describing the
underlying data in more details, but the data doesn't change. As previously seen, using this new metadata will end up in
the creation of new version of project which, without further consideration, would contain the exact same data file(s)
as the previous one. Blatant data duplication, waste of storage and money.

Data file duplication can be addressed by using ArtifactDB links. They work in a very similar way as symlinks on a POSIX
filesystem: ArtifactDB can create a link pointing to another ArtifactDB ID. In the example, a link in version 2 would
point to the data file in version 1. This is within the same project, but ArtifactDB links can also be used to refer to
files in other projects ("cross-projects" links). An important point to remember linking metadata is currently **not**
supported, only data files can be linked[^1].

The linking mecanism is currently initiated from the client itself. Though on the roadmap, there is no automatic data
deduplication happening on the backend side, which would inspects data files, find duplicated ones and automatically
create links. The client itself needs to know and provide linking information to the API. There are different ways to
achieve this: by providing ArtifactDB IDs directly or providing md5sum information [^2]

[^1]: though there can be duplication in metadata files, they are usually much smaller than data files, so the waste of
  storage is less important. What is more important there is the maintenance of the instance. Often
  an admin may need to open a metadata file for troubleshooting purposes (eg. that metadata file isn't indexed for some
  reason), having linked metadata would make that operation more complex, by manually resolving links. We loose a bit of
  storage in exchange of a more maintainable system.

[^2]: Another possibitly that might be implemented in the future in using file timestamps such as "mdtm" (modified
  datetime) and file size, though these don't provide good indication of uniqueness.

### Linking data with explicit ArtifactDB IDs

### Linking data using md5 checksum



## Permissions

The upload permissions are defined in two different places:

1. 

depends on depends on how the ArtifactDB API is configured, but generally speaking, uploading
data requires **write access**. That is, if a user wants to upload data, he has to be one of the owner of the project.


But what if the project doesn't exist? Another way to gain upload permissions is when the token contains the role
`uploader`. If that case, the API will grant permissions to upload data, whether it's an existing or a new project. This
is the most common scenario, where uploads are managed by service accounts with role `uploader`.


## Re-indexing

Re-indexing happens during upgrade and/or maintainance operations. This requires admin privileges, as this process is
available with the endpoint `/index/build`. During a global re-indexing, all the metadata is pulled from the storage and
sent to Elasticsearch. Depending on the size of the ArtifactDB instance and its metadata, this step can take several
hours.

Concurrent re-indexing is not allowed: the API puts a global lock in place, named `__all_projects__`, with a stage
`index_all`. The re-indexing needs to be completed, either with a success or failure, to release that lock before a new
re-indexing can be triggered. During that time, the endpoint `/index/status` will report `state: re-indexing` in the
response. Once done, that state can turn into `ok` (success) or `failed`. This state can be used to decide when to
update aliases (if using them) from old indices, to new freshly populated indices.

Note during a re-indexing, new projects, or new versions of existing projects can be added (with locking mechanism
specific to the projects applying, as explained above). Re-indexing *existing* metadata from a storage and adding *new*
metadata are two distinct processes, independent from each other. Namely, they don't the same impact in terms of
operational process, when new indices are being populated in the backend, while the frontend REST API still serves
existing metadata from the old indices (this is the main use case of re-indexing).

