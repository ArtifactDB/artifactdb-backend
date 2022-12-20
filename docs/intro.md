# Introduction

*ArtifactDB* is an "umbrella" name describing a type of API, built on top of the same open sourced
[framework](https://github.com/ArtifactDB). The concept is simple: secure storage of arbitrary data along with
searchable metadata. ArtifactDB instances live close to the business and help collecting, organizing, cataloging rich
domain-specific metadata. The data itself is by design treated as a "blob"

All ArtifactDB instances share the same features:

- Metadata must follow pre-defined JSON [schemas](schemas). These schemas correspond to data types. They are converted
  into "models" used to make this metadata searchable through an efficient indexing engine (Elasticsearch)
- Authentication is based on JWT tokens, traditionally provided by an OpenID provider (based on the standard OAuth2.0)
- Fine-grained [permissions](permissions) can be defined using a Role Base Access Control (RBAC) pattern, based on
  unixID, distribution lists, or AD groups.
- Data and metadata are organized and grouped as [projects](concepts/project), with [versioning](concepts/version)
  support (optional automatic provisioning of project identifiers and versions)
- Events are published during the data [lifecycle](concepts/lifecycle), allowing users and other systems to be notified
  and to react as needed.
- Each API provides unique Genomics Platform Resource Names, or [GPRNs](concepts/gprn) to easily refer to any given
  resources within the GP (artifacts, projects, versions, changelog, documentation, etc...)
- Extensible with backend [plugins](plugins), which can periodically run based on a schedule or based on certain events
  happening internally within ArtifactDB instances.
- Deployed as high performance, responsive and scalable REST APIs, built on top of Kubernetes, in the cloud.


