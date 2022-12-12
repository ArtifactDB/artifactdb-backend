# Administration pod

Most operations needed to interact with an ArtifactDB API can be performed using the REST API. Some critical, unusual,
unexpected operations may require access to an internal administration pod. This pod holds all the code currently
running the instance. Using a special script named `tools/admin.py`, a backend manager instance is created, allowing
to explore the instance by directly using ArtifactDB SDK python framework, within the instance's context.

The `tools/admin.py` script allows a wide range of usages, as it allows to interact and even program the instance,
accessing all its internals. Some useful commands are sometimes described in this documentation. Please also refer to
the [admin terminal](../usage/admin) section for more.

^ The `tools/admin.py` is available in backend, frontend, even if the admin pod is not enabled during deployment. A
admin user with access the Kubernetes namespace the instance is installed in can load that script and achieve the same
result as going through that admin pod and terminal. The main advantage of using an admin pod is to securely expose that
pod within a web browser, without having to onboard that user on the cluster.

## Web TTY (wetty) terminal

This administration pod is available when its deployment is enabled in the Helm chart during the instance deployment.
The pod's Docker image is the same as the frontend and backend pods. In addition, a
[wetty](https://github.com/butlerx/wetty) server is running[^1] and exposed as a service and an ingress route with the
path suffix `/shell`. Admin users can access the pod from a browser and "land" in the pod. They are authenticated based
on the Linux users created on the pod. A default list of admin users can be created as an Kubernetes secret, named
`admins-credentials` with a data filename `users.txt` in the following format:

```
user1:passwd1
user2:passwd2
```

After the creation of the users, the file content is passed to `chpasswd` to assign password. Passwords are listed in
clear, ie. not encrypted (which is fine since the Kubernetes secret is never exposed). If the content of that file is
empty, there's no admin users created at all. Any creation of users/passwd manually done from within the pod itself
(assuming the person doing this has access to the cluster) will not survice a pod restart, the `admins-credentials`
secret serves as a "database" for that purpose.

## Security and best practices

While the admin pod and terminal is not publicly accessible, the authentication is based on Linux login/password
combination. This should give enough security provided strong passwords are used. Yet, this admin terminal is probably
not useful most of time but only in some specific use cases and administration requests. It should *not* be made
available unless required. The Kubernetes deployment object can be used to scale it, with `0` to disable the terminal
(which would be the nominal state most of the time) and `1` to spin up an admin pod. This, again, requires access to the
cluster.

Another alternative, if the instance runs along with an Olympus Maintainer Operator[^2], is to create a maintenance
request on the API side, asking to scale the admin deployment to 0 or 1. The `PUT /maintenance/requests` endpoint can be
used, with the following payload:

```json
{
    "name": "scale-deployment",
    "args": ["admin",0]
}
```

where `admin` is the ArtifactDB component to scale, `admin` is this case, and `0` is the number of pod we want, here
scaling down to 0, disabling the terminal. `1` can be used to enable the terminal again. Values greater than 1 must be
avoided, there can be only one terminal at once.

The operator would then take care of that request automatically. Creating maintenance request requires the role `admin`
to be present in the JWT token. Since tokens are temporary and are different each time they're generated, the security
is improved when compared to leaving a pod running with static Linux user/passwd.

[^1]: Because not a single NodeJS application was designed to be easily installed, without major struggle, another
approach is used here to deploy that `wetty` application. An initContainer based on the official `wetty` image is used
to copy required executables, libraries and source code, into a shared Kubernetes volume. That volume is then made
available in the admin container itself. `wetty` is then started, within the python environment provided by the API
image.

[^2]: The Olympus Maintainer Operator is a Kubernetes operator responsible for keeping the instance healthy and perform
  maintenance operation.

TODO: link to deploy
TODO: link to admin shell usage

