# Permissions

Permissions play an important role in ArtifactDB, as they define who can access a set of artifacts, as well as who can
modify them. Permissions are defined using different fields, expressing *who* can do *what* on *which* resource.

The permissions "profile" corresponds to a file stored on the storage side (eg. AWS S3), within a version or project
folder, or at the root of the storage, depending on the "scope" (see below). When artifacts' metadata is indexed,
permissions are also fetched and injected into each indexed documents, under the key `_extra.permissions`. This
information is later used to perform authorized queries on the Elasticsearch index.

## Scope

Permissions are defined in a hierarchical way, according **scopes**.

- `version`: permissions apply to all files within a given version. This is the most
             granular scope (that is, permissions currently can't be set file by file).
             When accessing artifacts from a given version (actually, when propagating permissions
             from S3 to Elasticsearch, see [FAQ](#faq) below), `version` scope is first checked. If
             none could be found, it escalates to scope `project`. In other words, permissions
             inherits from upper scope if non-existant at current scope.

- `project`: permissions applies to all files within the project, that is, for all versions, unless
             some permissions were defined a version-level. If no permissions could be found at
             project-level, it escalates to the next upper scope `global`.

- `global`: top-level permissions scope. It's actually rare, and it can't be defined or changed by a
            user (this is by design, as it would open security issues), only an admin can do that.

It's important to remember that permissions aren't "merged" between scopes. You may want to declare
a set of owners at project-level, and let the read access be taken from the upper scope (global), but
that's not currently possible. If permissions are found at a given scope, ArtifactDB expects all permissions
rules to be defined at this level, it won't explore further up.

## Owners

`owners` field defines who owns the data, meaning having read *and* write access.  That includes: fetching data (read),
uploading files, changing permissions (write). Owners can be a list of unixID, distribution lists (DLs) or active
directory group (if configured in the ArtifactDB instance). That is, anyone part of the owners list, whether it's
directly through a unixID, or indirectly if belonging to a corresponding DLs or AD groups, will have read & write access
to the artifacts, at a given scope level.

For AD groups, the value must start with `CN=` in order to be considered as an AD group (which is reasonable, this is
close to AD syntax). More, depending on the company size, there could hundreds of AD groups a user could belong to. In
order to limit the number of checks performed against Elasticsearch (ie. resulting query size in terms filtering
conditions), AD groups must match a regular expression, defined at the configuration level, which is aimed at narrowing
down to only meaningful and useful groups in the context of the ArtifactDB instance.
    
`owners` field can be ommitted, it's optional, though it's a pretty rare use case, where common users would only access
artifacts in read-only mode, while admins (who can still access any artifacts, no matter what the permissions are) would
actually populate (write) the API with artifacts.

## Viewers

`viewers` field defines who can view the data. It basically defines read access, and follow the same rules as `owners`
in terms of content. `viewers` field is also optional.

## Access rules

Access rules can bring some more flavors to permissions. There are two access rules:

- `read_access`: defines who can "read" the data.
- `write_access`: define who can modify the data.

It's definitely closed to the notion of `owners` and `viewers`, and most of the time, `read_access = viewers` and
`write_access = owners`. But what if you want to allow anybody to view the data, in other words: public access? Or,
we may want to at least ensure the requesting user is authenticated. These cases can be handled respectively by setting
`read_access = public` or `read_access = authenticated`.

Another option is to set the access to `none`, so that nobody can access the data, in read mode if `read_access =
none`or write mode if `write_access = none`. The use case would be to remove the project (or version) from the
ArtifactDB, but keep the data, also referred as "hiding" a project.

Simply put, `read_access` and `write_access` actually defines who can read and write data, while `owners`, `viewers`,
`authenticated` and `public` can be seen as a set of users. Yes, it's possible to set `write_access = viewers`, which is
semantically weird, but in fact just means "give write access to the population of users defined in the group which happens
to be named viewers".

## Authorizing Elasticsearch queries

Once the user has been authenticated with the JWT tokens, the process continues with authorization, that is,
determinining what the user is allowed to access. Optional steps allow to enrich that steps with external information,
such as:

- Distribution lists (ie. mailling list): an external endpoint is used to obtain, given user's login/username, what
  distribution lists she's a member of.
- Active directory groups: similarly another endpoint, given the JWT user's token, can return all AD groups she belongs
  to. That information is then cached to avoid excessive queries.

Note: These endpoints mentioned abose are specific to the company's internal IT infrastructure, and may not be relevant
in every deployment.

This extra information is stored in a context variable, representing the current user for the time of the HTTP request
(see [authentication](auth)). When fetching or searching metadata, these information (username, list, groups) are
injected into the Elasticsearch query ("authorizing" the query) and used as filtering criteria. to implement
authorization at query time.  It interprets the value found in fields under `_extra.permissions` as follow:

- "owners": people listed in `_extra.permissions.owners` are allowed to access data.
- "viewers": people listed in `_extra.permissions.viewers`, or listed in `_extra.permissions.owners`, are allowed to
  access the data. An owner has at least the permissions of a viewer.
- "authenticated": as long as the user is properly authenticated, data access is granted
- "public": data can be accessed to anyone, even if not authenticated.


## FAQ

- **Wait, in the JSON documents, under `_extra.permissions` key, I can see the permissions, per file, and not according
  to the scope, how is that?**: It's a good question. There are two main sources of information: a storage like AWS S3,
  and Elasticsearch. Permissions profiles are stored in S3, as JSON files. During the indexing stage, permissions are
  fetched from S3, and propagated to Elasticsearch for each file.  It does so according to the different scopes.
  Elasticsearch now contains permissions for each file which allows to query data according to these, instead of
  fetching them from S3 on each access (which would be very inefficient, from a time and money perspective).

- **If permissions are defined in S3 and Elasticsearch, is there a risk they can be desynchronized?**: Yes, that's possible,
thought it would mean something really bad happened. Like manually editing the permissions on S3 without initiating
an indexing job to update Elasticsearch. Or maybe there could be a bug... The good news is there's an endpoint
to check if permissions are in sync, `/projects/{project_id}/version/{version}/permissions.

- **I don't really get the `global` scope thing...**: You can think about it as in a firewall: what is the final
rule to route traffic in case none of the previous rules matches? Here it's the same, if no permissions can be found,
what should ArtifactDB do? Allow access? Deny access? One use case scenario is when an ArtifactDB is entirely publicly
accessible, without any write access at  all (no permissions at all, on any scope other than the global one).  Another
scenario, the opposite in a way, is to have an ArtifactDB acting as a sandbox, where eveybody shares its data. No
permissions anywhere but the global-level one, with `write_access = public`.


