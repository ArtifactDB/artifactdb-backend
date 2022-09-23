# Configuration files

ArtifactDB configuration can be described in YAML files. The content is organized is different sections, targetting the
different components of an ArtifactDB instance, such as Elasticsearch, storages, schemas, etc... A single YAML file can
be used, but can also result in a lenghty content. To address this issue, the configuration content can optionally be
split across multiple files. These files are loaded and merged sequentially, based on the root-level keys representing
*sections* (see below), in alphatical order. If multiple files contains duplicated configuration content, the last one
merged one will take precedence.

## Sections

Throughout the rest of this document, these sections and their sub-fields within them are addressed using the
"dot-field" notation. For instance, the section `es` refers to the Elasticsearch configuration, found at the root level
of the configuration file. `es.frontend` refers to the sub-section `frontend`, found under the main `es` section, which
would be found in the YAML file as:

```yaml
es:
  frontend:
    ...
```

The configuration content is translated into a python structures based on the library
[aumbry](https://aumbry.readthedocs.io/en/latest/). Each section usually corresponds to one aumbry model, as well
as complex sub-sections. The final structure is assembled in a class named `ArtifactDBConfigBase`, mapping sections
found in the YAML files.


## `!include` constructor

A special YAML constructor allows the usage of the instruction `!include` followed by the path of another YAML file.
This enabled the inclusion of other YAML configuration elements, outside of the main configuration files, such as
encrypted secrets created during the deployment of the instance, preventing the exposure of password and such, a in
clear and unsecure way.

For instance, the file `/app/run/secrets/keycloak/svc-credentials.yaml` contains Keycloakd credentials for a service
account. In the context of a Kubernetes deployment, this file comes from a Secret object, injected in the pods
filesystem by Kubernetes itself. Without exposing these credentials, the following declaration can be used to inject
them at the configuration level:

```yaml
    service_account:
      credentials: !include /app/run/secrets/keycloak/svc-credentials.yaml
```

The resulting python dict structure contains the credentials in clear (so they can actually be used), but to prevent any
sensitive information leakage, through printing in logs for instance, all aumbry models derive from a custom
`artifactdb.config.utils.PrintableYamlConfig`, which handles redacting configuration data as necessary.

The `!include` constructor tag is a custom one, and trying to load a configuration file with a standard YAML loader will
fail because of that. Using the main entry point `artifactdb.config.get_config(...)` function allows to load
configuration files using such tags.

## Environment

By design, configuration files must include the environment in their filename, following the convention
`config-{env}.yml`. Enforcing this prevents from having generic files like `config.yml` being loaded and used,
whithout knowing if the content related to a development or production environment. The `{env}` information is usually
taken from an environment variable named `ARTIFACTDB_ENV`, set to the proper value when deploying the ArtifactDB
instance (eg. `dev` to load `config-dev.yml file). This is the recommended way, but `artifactdb.config.get_config(...)`
can take an argument `env` as input, for the same result.

## Patches

Configuration files are considered read-only, which is actually usually enforced by Kubernetes itself during the
deployment (`volumeMount` declared as `readOnly: true`). In some cases, it's useful to modify or enrich the
configuration content. This can be achieved by adding files containing JSON patch operations. These files must follow
the naming convention `patch-{env}-{section}.yml`. For instance, the patch config file `patch-dev-es.yaml` content:

```yaml
- op: add
  path: /es/frontend/clients/v2
  value:
    alias: myapi-dev-v2
```

instructs the configuration loaded to `add` and frontend client named `v2` in the `es.frontend` section, and
this client should use an Elasticsearch alias named `myapi-dev-v2` (more on the configuration itself in the
Elasticsearch and indexing part). The resulting patched configuration would look like

```yaml
es:
  frontend:
    clients:
      # content coming from the "read-only" config file
      v1:
        alias: myapi-dev-v1
      # content coming the patch config file, once the JSON patch operations were applied
      v2:
        alias: myapi-dev-v2

```

During the starting process of the instance, configuration files are loaded, then optional patches are applied in
alphetical order, on top the configuration content.

This section was aiming at explaining the configuration options and mecanisms available to "shape" and customize an
ArtifactDB instance. The actual content and documentation of each fields are adressed in the corresponding sections
later in the documentation.
