# Backend components

The ArtifactDB server-side components are known as the "ArtifactDB backend". This naming comes from the facts multiple
clients can talk to the server REST API, enforcing client vs. backend distinction. That said, the server components
themselves can be decomposed into "frontend" and "backend" elements:

- *frontend*: everything relating the REST API, public facing. That's the server-side component the clients are talking
  to.
- *backend*: evertyhing that is happening behind and beyond the frontend, most of the time, as asynchronous tasks.

This section describes this backend component specifically.


## Backend Manager

The backend component is organized around a "manager", gathering multiple sub-components by composition. Some of these
sub-components are required, some have dependencies between each others, and some are optionals but add specific
features (eg. external integration, instance-specific features, etc...). Creating a backend manager instance requires
some modularity to fit the different use cases and to allow extendibility. This flexibility is implemented following a
pattern closed to the ["Builder Pattern"](https://en.wikipedia.org/wiki/Builder_pattern), to allow the creation of a
manager instance, in a orderly, "chainable" manner, such as:

```python
import artifactdb.backend.managers.base
import artifactdb.backend.sequences
import mycustom.builder.notifications

manager = artifactdb.backend.managers.base.BackendManagerBase()
            # activate sequences (project IDs and versions provisioning)
            .build(artifactdb.backend.sequences.SequenceManager)
            # integration with a custom notification system
            .build(mycustom.builder.notifications.Notifier)
```

Alternately, the list of components can be declared in a class deriving
`artifactdb.backend.managers.base.BackendManagerBase`. The list will be processed in order during this instance
creation.

```python
class ArtifactDBBackendManagerBase(BackendManagerBase):

    COMPONENTS = [
        {"class": mycustom.builder.notifications.Notifier, "required": False},
        ...
    ]
```

The whole configuration is provided to the sub-component during its instantiation, it's the responsability of the
sub-component to select which part(s) of the configuration should be used. The dependencies that may exists between
these sub-components are adressed with the order by which the `build(...)` calls happen.

Each time a new sub-component is added, one or more *feature* can be registered as well. In the previous example, such
*features* could be `"auto-provisioning"` and `"notifications"`. These features are later exposed by the REST API to
inform users and clients of the instance capabilities currently available.

