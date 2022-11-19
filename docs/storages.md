# Storages

Storages play an important role in ArtifactDB, as they are considered the source of truth, for any data, metadata and
other administrative metadata (permissions, links, revisions, etc...). Storages are traditionally blob-store living in
the cloud, namely AWS S3 for instance. While this is currently the only storage type implement, it's possible to
implement more (other blob-store on Azure, GCP, filesystems, or even another ArtifactDB instance).

By design, there is no database, everything is stored on the storage(s). While there is an indexing engine, like
Elasticsearch, handling searches over metadata, this can be seen a duplication of metadata stored in an optimized
database. Should an index be deleted, the REST API would certainly be impacted, but there would be not data loss, since
only the duplicated data is lost.

The other important advantage of this approach is it's easy to understand the content of that storage. After all, an
ArtifactDB instance is a receptacle of data and metadata files uploaded by a client, there is no transformation, no
modification, no data/metadata deconstruction into an internal, possibly cryptic data model hidden in the system.
Transparency is key when it comes to data management, what you upload if what you download. This approach reduces
"vendor lock-ins", data can be migrated to another system if necessary, starting from the original content uploaded
initially. This also allows data migration to storage in the cloud, using a temporary ArtifactDB instance for that
matter, before getting rid of it once done.

## Content structure

ArtifactDB hold data and metadata, organized by **projects**, each project can then have multiple **versions**. This is
reflected on the folder structure on the storage: one folder per project, one folder per version within a project. 

Ex: this storage contains 2 projects, `PRJ00001` with 2 versions (`VER0001` and `VER0002`) and `PRJ00003` with one
version (`VER0009`)
```
/PRJ00001/VER0001
/PRJ00001/VER0002
/PRJ00002/VER0001
```

This contrived example illustrates different aspects:

- By convention, projects have a so-called **prefix**, here `PRJ`. One instance can hold more than one prefix (eg. `PRJ`
  and `test-PRJ` to isolate testing data by naming conversion for instance). There could be padding zero like here, or
  not (`PRJ1`, `PRJ2`, etc...) depending on the convention put in place in the instance.
- The version is not necessarily an integer. It's actually always treated as a string and can be anything (one example
  would be a Git commit hash).
- If the instance supports auto-provisioning using one or more [sequence(s)](sequence), these project IDs and versions
  can be provisioned by the instance, in a transactional way.
- Project IDs and versions may not be sequential, even using auto-provisioning. If an upload fails, the provisioned
  project ID and/or version is lost, and new ones will be provisioned on the next try.
- Finally, there is currently no way to overcome this structure, there has to be a project folder, and within it, at
  least one version folder.

Back on the subject of versioning, how to order versions if they're string and can be anything? How to know which
version is the latest? During the [upload](usage/upload) process, ArtifactDB assigns a **revision** along side the
version. This revision can be seen as a human readable version, and also provides a way to determine the numerical value
of the version, by parsing its value. For instance, assuming an instance provides revision in the format `REV-x` (each
instance can be their own way to declare revision format), where `x` is an integer, a version `a1b2c3d4f5g` could have
the revision `REV-3` assigned during the upload. The resulting numerical revision would be `3`. The API uses this
information to determine the order the versions, and the latest one. As any data, metadata and internal metadata files,
this revision information stored on the storage, in each version folder, in `..meta/revision.json` internal metadata file.

Ex: example of a `..meta/revision.json` file content
```
{
    "revision": "REV-3",
    "numerical_revision": 3
}
```

## Storage types

ArtifactDB is currently heavily oriented towards AWS cloud support, as such, the main storage currently supported in AWS
S3. The design itself allows implementation of other storage types (GCP or Azure blob-stores, local filesystem).


## Multi-storages

Multiple storages can be declared in an instance. There are many different use cases that benefits from that features,
which goes beyond the scope of the document, but to name a few, we can mention data migration, API data versioning, data
replication, archiving, etc...

At any point in time though, there is currently only one *active* storage[^1]. For instance, when accessing the REST API and
fetching data, only one storage can serve that data. The selection of a specific storage can done in different ways:

- A so-called "switch" parameter can be used to specify, depending on the value an HTTP header, which storage should be
  used (see below the configuration section). Uploading, accessing data can be done by specifying this header (or
  through proxy rules which can set the header depending on the prefix path for instance).
- Project indexing from a specific storage can be achieved using the admin reserved endpoint `/index/build`, which
  accepts a `storage` parameter for the storage alias.

The data location is revealed in the internal metadata `_extra.location`, for each JSON document served by the API,
indicating the type and information about the storage itself:
```
"_extra":{
    "location":{
        "type":"s3",
        "s3":{
            "bucket":"mybucket-v3-uat"
        }
    },
    ...
}
```

## Configuration

The storage configuration can be found under the `storage` section of the configuration file.

- `storage.clients` lists the different storages themselves.
- `storage.switch` declares the rules to switch between storages.

### Storages 

Each storage must declare:

- a unique `alias` (amongst other storages in the instance)
- a `type` (ex. `s3`)
- and a key named after the type (eg. `s3`). Depending on the type, the value associated to that key changes. For AWS S3
  (`type: s3`):
  - `endpoint`: custom S3 endpoint, if not using the default one (or if using another implementation of S3)
  - `bucket`: bucket name
  - `credentials`: dictionary containing the credentials to access the bucket.
  - `presigned_url_expiration`: default TTL in second for presigned-URLs
  - `signature_version`: specific signature version (eg `s3v4`), useful for instance when KMS is involved for the
    encryption of the bucket itself).
  - `region`: preferred region to access the bucket.
  - `delete_stale_projects_older_than`: clean failed (stale) uploaded project (no properly completed, marked as
    "to-be-deleted"), after a certain amount of time (eg. "in 2 weeks", meaning all stale projects older than two weeks
    will be purged). The value must be parsable by the python library
    [dataparser](https://dateparser.readthedocs.io/en/latest/).
  - `bucket_versioning`: ternary value
    - `null` (default): the bucket versioning configuration is left intact
    - `true`: bucket versioning is enabled
    - `false`: bucket versioning is disabled

### Switch

When using multiple storages, a switch can be used to specifcy which one to use depending on the request.

### Example

The following example illustrates the usage of multiple storages when upgrading an API. Let's say the API in question
needs a significant upgrade, from v2 to v3, which involves breaking changes on the metadata and/or data structure. We
still want to keep the v2 data, even serves it as a backward compatibility courtesy. Using two different buckets also
make the transition easier, as opposed to mixing v2 and v3 data into the same bucket.

We declare two storages, with an alias `v2` and `v3`, as followed. When accessing the REST API, we can specify a custom
HTTP header named `X-MyAPI-Version`. When `v2`, the switch rule sets a storage context with the value of the
corresponding alias ("v2" in header mapped to storage alias "v2"). Same for v3.

```
storage:
  clients:
  - alias: v3
    type: s3
    s3: 
      bucket: myapi-v3
      credentials: !include /app/run/secrets/s3/credentials.yaml
      signature_version: s3v4
      region: us-west-2
  - alias: v2
    type: s3
    s3: 
      bucket: myapi-v2
      credentials: !include /app/run/secrets/s3/credentials.yaml
      signature_version: s3v4
      region: us-west-2
  # v2/v3 switch (matching X-MyAPI-Version header)
  switch:                                                                                                                                                                                                                                                                                                                                                                                                                                
    header: X-MyAPI-Version
    contexts:  # matching a client alias
      v2: v2
      v3: v3
```



## Limits

Limitations, such the max number of files, max total storage size, max total size per file is directly dictated by the
storage itself. For AWS S3, a single file cannot be more 5TB (this requires multi-part uploads, easily handled using STS
credentials for instance), or 5GB using a single pre-signed upload URLs.

[^1]: A future implementation might overcome this limitation.
