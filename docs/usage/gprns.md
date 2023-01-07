# Exploring GPRNs

The [identifiers](../design/identifiers) section describe what a GPRN is, while this section describes how to use
`/gprns` endpoints available in ArtifactDB APIs.

## Validating a GPRN

As a utility or helper, the endpoint `GET /gprn/{gprn}/validate` can be used to make sure a GPRN is valid. Few
examples:

```bash
# valid GPRN
$ curl https://dev.myapi.mycompany.com/gprn/gprn:dev:myapi::artifact:PRJ00000022:experiment-1/assay-2.h5@3/validate
```
```json
{
    "status": "ok"
}
```

```bash
# invalid GPRN (`type-id` is `artifact` but should be `project`, because the `resource-id` is not an ArtifactDB ID)
$ curl https://dev.myapi.mycompany.com/gprn/gprn:dev:myapi::artifact:PRJ00000022/validate
```
```json
{
    "status":"error",
    "reason":"unable to parse ID"
}
```

```bash
# incorrect environment (the GRPN refers to MyAPI "production", but the instance serves MyAPI "development")
$ curl https://dev.myapi.mycompany.com/gprn/gprn::myapi::project:PRJ00000022/validate
```
```json
{
    "status":"error",
    "reason":"Invalid 'environment'"
}
```

Validating a GPRN doesn't require authentication, as this only operation involved is the parsing (there's no underlying queries
happening).


## Locating a GPRN

Since ArtifactDB APIs stores data on AWS S3 any artifact, project and version, or just a project, corresponds
to a specific S3 URL and ARN. The endpoint `GET /gprn/{gprn}/locate` provides such locations. Obtaining the location
of a GPRN requires permissions to access the GPRN in the first place, this endpoint is thus under authentication.

The following example shows how to determine the location of different GPRNs.
```bash
# Locating a HDF5 file, part of a dataset
# GPRN is: gprn:dev:myapi::artifact:PRJ00000022:experiment-1/assay-2.h5@3
$ curl https://dev.myapi.mycompany.com/gprn/gprn:dev:myapi::artifact:PRJ00000022:experiment-1/assay-2.h5@3/locate
```
```json
{
  "s3_url": "s3://my-bucket/PRJ00000022/3/experiment-1/assay-2.h5",
  "s3_arn": "arn:aws:s3:::my-bucket/PRJ00000022/3/experiment-1/assay-2.h5"
}
```

```bash
# Locating a project+version folder
# GPRN is: gprn:dev:myapi::project:PRJ00000022@3
$ curl https://dev.myapi.mycompany.com/gprn/gprn:dev:myapi::project:PRJ00000022@3/locate
```
```json
{
  "s3_url": "s3://my-bucket/PRJ00000022/3/",
  "s3_arn": "arn:aws:s3:::my-bucket/PRJ00000022/3/"
}
```

Note a "revision" (eg. `NUM-3`) can also be passed as version information in the GPRN, this locate endpoint will resolve
the "revision" to the actual "version", corresponding to an existing folder on S3.

By default, existence of S3 keys is verified, this can be bypassed by specifying the query string parameter `?check=false` (useful in
some use cases involving provisioning).


## Obtaining parents lineage

Within an ArtifactDB API, an artifact belongs to a version, which belongs to a project. This lineage information can be
obtained using the endpoint `GET /grpn/{gprn}/parents`.

```bash
$ curl https://dev.myapi.mycompany.com/gprn/gprn:dev:myapi::artifact:PRJ00000022:experiment-1/assay-2.h5@3/parents
```
```json
[
    {
        "type":"version",
        "gprn":"gprn:dev:myapi::project:PRJ00000022@3"
    },
    {
        "type":"project",
        "gprn":"gprn:dev:myapi::project:PRJ00000022"
    },
    {
        "type":"projects",
        "gprn":"gprn:dev:myapi::project"
    },
    {
        "type":"service",
        "gprn":"gprn:dev:myapi"
    }
]
```

This endpoint doesn't require authentication, as the process only involves parsing the GPRN.

## Obtaining children lineage

In the same way as parents lineage, given a GPRN, its children can be obtained using the endpoint
`GET /gprn/{gprn}/children`. This endpoint may require authentication in order to query and determine
children. Also, the maximum number of children is currently limited to 250 by default, should this limit
reached, a `partial_results: true` would be present in the response.

```bash
$ curl https://dev.myapi.mycompany.com/gprn/gprn:dev:myapi::project:PRJ00000043/children
```
```json
{
  "children": [
    "gprn:dev:myapi::artifact:PRJ00000043:dataset.json@1",
    "gprn:dev:myapi::artifact:PRJ00000043:experiment-1/assay-1.hdf5@1",
    "gprn:dev:myapi::artifact:PRJ00000043:experiment-1/assay-2.hdf5@1",
    "gprn:dev:myapi::artifact:PRJ00000043:experiment-1/coldata/simple.csv@1",
    "gprn:dev:myapi::artifact:PRJ00000043:experiment-1/experiment.json@1",
    "gprn:dev:myapi::artifact:PRJ00000043:experiment-1/rowdata/simple.csv@1",
    "gprn:dev:myapi::artifact:PRJ00000043:sample_data/simple.csv@1",
    "gprn:dev:myapi::artifact:PRJ00000043:sample_mapping.csv@1"
  ]
}
```

Note it's not possible to request children of a GPRN "higher" than one pointing to a specific project, eg. trying
to obtain children of all projects will return an error:
```bash
$ curl https://dev.myapi.mycompany.com/gprn/gprn:dev:myapi::project/children
```
```json
{
  "status": "error",
  "reason": "Requesting children without a resource-id component is not allowed (for now)"
}
```

## Checking permissions

In order to know if a given user (through his/her JWT token), the endpoint `GET /gprn/{gprn}/permissions` can be
used. It returns a `HTTP 200` if allowed, or `HTTP 404 Not Found` if the user isn't allowed to access it or if the GPRN
doesn't exist within the API.

Note: the status code 404 "Not Found" is returned instead of a 403 "Not authorized". This is
by design: an ArtifactDB API doesn't reveal whether an artifact exists if the requester isn't allowed to access it. This logic
is somewhat similar to a firewall rule dropping packets (we don't know if the target exists) instead of rejecting them (we know the target
exists but we get a explicit deny, which is informative on its own).

```bash
$ curl https://dev.myapi.mycompany.com/gprn/gprn:dev:myapi::project:PRJ00000043/permissions
```
```json
{
  "allowed": true
}
```

When not allowed (or the GPRN doesn't exist):
```bash
$ curl https://dev.myapi.mycompany.com/gprn/gprn:dev:myapi::project:DS000006849/permissions
```
```json
{
  "status": "error",
  "reason": "No such GPRN"
}
```

Checking permissions on a GPRN "higher" than a specific project is not allowed:
```bash
$ curl https://dev.myapi.mycompany.com/gprn/gprn:dev:myapi::project/permissions
```
```json
{
  "status": "error",
  "reason": "Requesting permissions without a resource-id component is not allowed"
}
```

