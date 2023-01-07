# Identifiers

## ArtifactDB ID

ArtifactDB ID, also referred as `aid` uniquely identifies an artifact within an ArtifactDB instance. Its syntax is as
follows:

```
<project_id>:<path>@<version>
```

When translated to a location in a storage such as S3, it corresponds to the following filename:

```
<project_id>/<version>/<path>
```

Example:
```bash
PRJ2:folder1/one.file-2.csv@8b60b19b58ef9de4de2e4e8ed8673a4e59491b53
```

where:
- `PRJ2` is the project ID
- `folder1/one.file-2.csv` is the file path
- and `8b60b19b58ef9de4de2e4e8ed8673a4e59491b53` is the version

These different parts can be found in the internal ArtifactDB metadata key [`_extra`](../usage/extrameta), in each

Note: ArtifactDB IDs are ensured by design to be unique within an instance, not across instances.


### Project ID

The component `project_id` represents a project name, unique per instance. Project name can include letters, usually
uppercased by convention, and digits. Specifically, the following characters are not allowed: `/`, a leading `_`,
A prefix is also used as a convention, eg. `PRJ`, `ADB`, `DS`, etc... to indicate the type of the project, as a hint.
A single ArtifactDB instance can hold multiple project prefixes, see section about [sequences](sequences) for more.

### Version

Versions are assembled under a project ID, represent by the component `version` at the end of an ArtifactDB ID, after
the `@` character. It can be composed of digits or letters.  The same excluded characters listed in `project_id` applies
there as well.

A revision name can also be used instead of a version, as a sort of aliasing mechanism. This becomes useful when
versions are not human-friendly, such as commit hash. Revision are always generated and assigned by the ArtifactDB
instance each time data is [uploaded](../usage/upload). For instance, the version holding a commit hash
`8b60b19b58ef9de4de2e4e8ed8673a4e59491b53` could also be represented by the revision `NUM-3` (assuming this is the third
upload), easier to remember. See also the [storages](storage) section for more on revision and their structure.

#### Latest revision

A special value, `latest` (or `LATEST`), can be used to point to the latest revision of a project or file. `latest` can
be used anywhere instead of a version or revision number, and is a useful way to point the latest artifacts. A little
bit like the tag "latest" in Docker registries...

Ex: if version `8b60b19b58ef9de4de2e4e8ed8673a4e59491b53`, as revision `NUM-3` is the latest found in project `PRJ2`, the following 
ArtifactDB ID all represent the same file:

```
PRJ2:folder1/one.file-2.csv@8b60b19b58ef9de4de2e4e8ed8673a4e59491b53
PRJ2:folder1/one.file-2.csv@NUM-3
PRJ2:folder1/one.file-2.csv@latest
PRJ2:folder1/one.file-2.csv@LATEST
PRJ2:folder1/one.file-2.csv@lAtEsT
```

The special version or revision `latest` is useful to always point to the latest data, but not to refer to a specific
version. This is important to keep that in mind when running data workflow for instance: if more versions are created,
`PRJ2:folder1/one.file-2.csv@latest` would then point to a different version, potentially impacting the reproducibility
of the workflow if that one was using a `latest` version tag instead of an explicit version name.


### Path

The component `path` is the filename path within the version. It can point to a subdirectory structure, can contain `/`
as the traditional delimiter for folders.



## Genomics Platform Resource Names (GPRNs)

GPRNs are inspired by Amazon AWS [ARNs](https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html) and uniquely
identify a resource within the ArtifactDB Platform. This nomenclature is used by ArtifactDB instances themselves, but
also other component of the platform. The name comes from where it originated, the Genomics Plaform, but the "GP" part
can easily stand for other more generic names, like "Generic Product", "Global Product", "Great Platform", etc...

A resource is a generic term describing "something" within the platform. It can be an artifact in an ArtifactDB API, it can
be an API, an API on specific environment, etc... The format is the following, with some segments being optional or defaulting
to specific values or meaning. When omitted, the number of `:` within the GPRN must be kept (this produces things like `::`):

```
gprn:environment:service:placeholder:type-id:resource-id
```

- `gprn`: prefix, mandatory
- *environment*: optionally specify the environment on which the resource can be found. Example: `dev`, `tst`, `prd`, etc...
  If omitted, the environment is the production.
- *service*: mandatory. The service, application, api, etc... on which the resource can be found. Ex: `myapi`, `yourapi`, etc...
- *placeholder*: is a placeholder, in case another segment is required. (it's `region` in original ARNs)

At the point, the segments allow to uniquely describe a service, on a specific environment. Ex:
- `gprn::myapi` means "MyAPI service, production environment"
- `gprn:dev:yourapi` means "YourAPI service, development environment"
- `gprn::yourapi:europe` means "YourAPI service, production, located in Europe"

Continuing further, we can describe resources within services:
- *type-id*: optional if *resource-id* not specified, otherwise required. Type of resource described in *resource-id*
- *resource-id*: optional if *type-id* not specficied, otherwise required. ID of type *type-id* within the service.

Ex:
- `gprn::myapi::artifact:PRJ2:result.html@PUBLISHED-3` means the Artifact ID `PRJ2:result.html@PUBSLIHED-3` in MyAPI, production.
- `gprn::myapi::project:PRJ2` means project PRJ2 within MyAPI, production
- `gprn::myapi::project:PRJ2@NUM-3` means project `PRJ2`, version `NUM-3`, within MyAPI, production
- `gprn::myapi::doc` means the documentation for MyAPI API.

GPRNs can found in metadata returned by ArtifactDB APIs, which also provide dedicated [endpoints](../usage/gprns)
to help manipulating them.

