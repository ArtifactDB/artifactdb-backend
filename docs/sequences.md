# Sequences and auto-provisioning

In the ArtifactDB world, data and metadata files are organized in projects, then versions. This means project must have
unique IDs across them, and versions within a single project must also be unique. There are different options achieving
this requirement: external provisioning vs. auto-provisioning.

## External provisioning

The uniqueness of projects ID and versions are left to the client interfacing wit the ArtifactDB instance. This is
useful for instance when these identifiers are stored and managed in an external system. The instance will not provision
any IDs, nor will it ensure an existing project is not being overwritten. It just trusts and follow the directions
communicated by the client.

## Auto-provisioning

When this component is enabled, a `artifactdb.backend.components.sequences.SequenceManager` is created and attached to
the backend manager. This manager holds one or more `artifactdb.backend.components.sequences.SequenceClient` responsible
to provision project identifiers, and for each, unique versions, in a transational way. The underlying implementation
involves a SQL database and a sequence (if Postgres), so the name. The library `sqlalchemy` is used for the SQL database
operations. A sequence for a project ID is usually defined as a project prefix (eg. `PRJ`, `DS`, etc...), while the
version is based on on incremented integer, per project.

### Synchronizing

Following one of the core principle of ArtifactDB, "the storage (like s3) is the source of truth", the whole SQL
database content can be derived from the storage content. Projects and their versions are listed and used to populate
the initial content. During that "sync" operation, the table containing the actual sequence information is locked, to
prevent any concurrent writing (a new project being created while syncing the sequences). Any request for provisioning,
ie. any upload requests, will hang until the sequence content is restored from the storage. This operation can take a
long time, and the instance should be put in a maintenance mode to inform users new uploads should be postponed.

Each `SequenceClient` is associated, per configuration (see below), to one sequence content. The synchronization process
is performed from the sequence client, which means if multiple sequences are declared (eg. multiple prefixes), each can
be synchornized independently from the others.

TODO: link to "Maintenance mode"


### Pools

Pools declare intervals to contrain project identifiers values. They come in two different flavors:

- *provisioned pool*: declares an inclusive interval within which a project ID will be provisioned. There can be only
  active provisioned pool, if a new provisioned pool is created, the previous one will set to `inactive`.
- *restricted pool*: declares an inclusive interval within which a project ID is *not* allowed to be provisioned. There
  can be multiple restricted pools at a time.

Restricted pools can overlap a provisioned pool, in which case the overlapped IDs are removed from the provisioning
process (in other words, restricted pools have precedence over provisioned pools).

When starting for the first time, the ArtifactDB instance will create a provisioned pool ranging from 1 up to
`max_sequence_id`, with 999'999'999 being the default (see configuration below for more).

TODO: image pools


### Interfaces

#### API endooint

There are multiple REST endpoints involved.

- `POST /projects/upload` is used to ask the instance to provision both a project ID and a version.
- `POST /projects/{project_id}/upload` is used to provision a new version within an existing project. It will fail if
  that project doesn't exist.
- `POST /projects/{project_id}/version/{version}/upload`, see below the different use cases

The first two endpoints require, by default, the role `creator`, to limit, if necessary, the process of project creation
to a set of users. Upon project and/or version provisioning, the endpoint redirects to the same endpoint, the third one,
`POST /projects/{project_id}/version/{version}/upload`. This endpoint is also used with external provisioning (not
auto-provisioning), where `project_id` and `version` are provided by the client. To prevent everybody from this
endpoint, possibly overwriting or corrupting an existing project, the role `uploader` is required in the default
authorization configuration.

This last endpoint requires the role `uploader`, but going through auto-provisioning and with the first endpoints
`POST /projects/upload` and `POST /projects/{project_id}/upload`, the role `creator` is required. Yet both these
endpoints will redirect to the one requiring `uploader` permissions. How so?  The instance uses an internal pre-signed
URL mechanism to temporarily promote the user's role to `uploader`, specifically and only for that request (the
pre-signed upload URL can't be reused for other projects).

TODO: other /sequences endpoints

TODO: link to "Uploading data and metadata" section
TODO: link to "Internal pre-signed URL" section

#### Configuration

Using a sequence requires to declare a list of configuration elements. Each element of that list will produce a
`SequenceClient`. The `uri`, `db_user`, `db_password` and `schema_name` parameters specify the database access are
roughly passed to `sqlalchemy.create_engine(...)` function. The remaining parameters drive the sequence behavior,
specifically the project ID naming.

```yaml
  sequence:
    - uri: postgresql+psycopg2://...
      db_user: postgres
      db_password: !include /app/run/secrets/pg/postgresql-password
      schema_name: mysequence
      project_prefix: PROJ
      project_format: 'f"{project_prefix}{seq_id:09}"'
      default: true
    - ...
```
TODO: doc for max_sequence_id, version_first, auto_create_pool, default, debug

In this example, the `project_prefix` instruct that all project IDs will start with `PROJ`, while the f-string notation
found in `project_format` adds 9 digits. The `seq_id` is passed by the sequence client itself and corresponds to the
incremented integers returned by the SQL sequence itself. The whole f-string is then `eval`'d to obtain the final
result. The version format is left to the sequence client implementation (default is an incremented integer).

#### Administration

Sequences can be manipulated from an *admin* pod to perform maintenance operations. Because these operations are rare
and critical, there are not available through endpoints. Let's see some examples.

**Manipulating provisioned and restricted pool**

```
# list sequence clients
> mgr.sequence_manager.clients
{'RDB': <SequenceClient (schema='rdbseq_dev_rdb', prefix='RDB', default=True)>,
 'test-RDB': <SequenceClient (schema='rdbseq_dev_test_rdb', prefix='test-RDB', default=False)>}
# fetch the sequence client we're interested in
> seq_client = mgr.sequence_manager.clients["RDB"]
# list existing pools
> seq_client.list_provisioned_pools()
[{'pool_id': 1,
  'pool_type': 'PROVISIONED',
  'pool_status': 'ACTIVE',
  'lower_limit': 2,
  'upper_limit': 999999999,
  'created_at': datetime.datetime(2022, 6, 21, 19, 47, 5, 898703, tzinfo=psycopg2.tz.FixedOffsetTimezone(offset=0, name=None))}]
> seq_client.list_restricted_pools()
[]
# check current project ID
> seq_client.current_id()
"RDB000000003"
# obtain a new one
> seq_client.next_id()
'RDB000000004'
# the next one would 5, etc... Let's restrict this and forbids provisioning from [5,1O]
> seq_client.create_restricted_pool(5,10)
> seq_client.list_restricted_pools()
[{'pool_id': 2,
  'pool_type': 'RESTRICTED',
  'pool_status': 'ACTIVE',
  'lower_limit': 5,
  'upper_limit': 10,
  'created_at': datetime.datetime(2022, 9, 27, 17, 31, 55, 92508, tzinfo=psycopg2.tz.FixedOffsetTimezone(offset=0, name=None))}]
# the restricted pool overlaps the provisioned one, next ID is...
> seq_client.next_id()
'RDB000000011'
# indeed, not 5 but 11! Let's create a new provisioned pool
> seq_client.create_provisioned_pool(100, 200)
# list all provisioned, regardless of `pool_status`
 seq_client.list_provisioned_pools(pool_status=None)
Out[16]:
[{'pool_id': 3,
  'pool_type': 'PROVISIONED',
  'pool_status': 'ACTIVE',
  'lower_limit': 100,
  'upper_limit': 200,
  'created_at': datetime.datetime(2022, 9, 27, 17, 33, 38, 519968, tzinfo=psycopg2.tz.FixedOffsetTimezone(offset=0, name=None))},
 {'pool_id': 1,
  'pool_type': 'PROVISIONED',
  'pool_status': 'INACTIVE',
  'lower_limit': 2,
  'upper_limit': 999999999,
  'created_at': datetime.datetime(2022, 6, 21, 19, 47, 5, 898703, tzinfo=psycopg2.tz.FixedOffsetTimezone(offset=0, name=None))}]
# the old one is now inactive, the new one active. Next ID is...
> seq_client.next_id()
'RDB000000100'
```



TODO: link to "admin pod"

