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
some modularity to fit the different use cases and to allow extendability. This flexibility is implemented by declaring
the component classes at the manager's class level, the manager itself, during its instanciation, builds the
sub-components and integrates the 

```python
import artifactdb.backend.managers.base
import artifactdb.backend.sequences
import mycustom.builder.notifications

class MyBackendManager(artifactdb.backend.managers.base.BackendManagerBase):

    COMPONENTS = [
        {"module": artifactdb.backend.sequences, "required": True},
        {"module": mycustom.builder.notifications, "required": False}
    ]
```

This example declares a `MyBackendManager` class with two components, one required, one not required. When a component
is required, if its creation fails, the whole backend manager instanciation is declared failed. Failures for
non-required components are logged but ignored. During initialization, the manager will inspect the modules declared in
the list `COMPONENTS`, looking for classes inheriting from either:

- `artifactdb.backend.components.BackendComponent`: the whole component logic is fully implemented in the component
  class itself, including the constructor.
- or `artifactdb.backend.components.WrappedBackendComponent`: this class acts as a wrapper over an existing class living
  outside of the the context of backend components. The constructor and wrapping logic is taken care of the
  `WrappedBackendComponent`, only the method `wrapped()` requires to be implemented in the sub-class. For instance,
  `ElasticSearchManager` is an important element of an ArtifactDB API responsible for querying, indexing data. It lives
  on its own, is used by the REST API. A wrapped component is typically used in this case to easily convert this class
  into fully functional component.

Either ways, the whole configuration and the backend manager instance itsefl are provided and made available to the
sub-component during its instantiation, it's the responsability of the sub-component to select which part(s) of the
configuration should be used. The dependencies that may exists between these sub-components are adressed with the order
by which they appear in the `COMPONENTS` list.

Each time a new sub-component is added, one or more *feature* can be registered as well. In the previous example, such
*features* could be `"auto-provisioning"` (sequence number, that is, project IDs), and `"notifications"`. These features
are later exposed by the REST API to inform users and clients of the instance capabilities currently available.

During the backend and its components initialization, several "hooks" can be implemented to enrich this step, at
different stages. Indeded, it is not rare that a component needs extra initialization steps later, after its own
creation. The following hooks are called in `artifactdb.backend.app.get_app()`, which is the main entry point in the
backend to initialize the backend manager and link it to the main Celery application. The following hooks are called for
each successfully registered components:

- `component_init()`: this method is called just after the component instance has been created, while the components are
  discovered and registered.
- `post_manager_init()`: this method is called just after the backend manager instance has been created. Components are
  fully registered at that point, but the backend tasks (Celery tasks) are not registered yet. This hook is useful when
  a component needs to prepare some work before these tasks, for instance pulling their code from Git repositories
  (that's what the `PluginsComponent` does)
- `post_tasks_init()`: once tasks are registered, this method is called. This hookd is useful for instance to obtain
  information about these tasks (this is what the `TasksComponent` does).
- `post_final_init()`: finally, before returning the final Celery application and its linked backend manager, this
  method is called for "last-call init".

## Transient 
