# Authentication

ArtifactDB REST API provides authentication based on JWT (JSON Web Token) and the OpenID Connect implementation. A JWT
is an encoded and signed JSON document, containing header and claims. The header contains references to the public key
that can be used to verify the signature, while the claims contains the actual payload: the name of the user, the client
ID, the roles, etc...

Upon reception of an HTTP request from a client, a FastAPI "authentication" middleware intercepts that request to extract the
authentication information. Specifically, it expects that such information, if present, must be found in the header
`Authorization`, with a value looking like `Bearer token_string` [^1]. The auth middleware proceeds by validating the
token string, by downloading (then caching) the public key ID `kid` found in the JWT header.

The configuration regarding authentication allows to declare different so-called "well-known" URLs, which according to
the OpenID standard, must provide URL to the content of the public key as well as its `kid`. To allow flexibility in the
JWT sources, the configuration allows to declare:

- one primary well-known URL: this is the main one, used to authenticate users through Swagger (section
  `auth.oidc.well_known.primary`).
- several secondary well-known URLs: alternately, these URLs are used to also verify the signature (section
  `auth.oidc.well_known.secondary`).

These public keys don't change often and constantly fetching their value would be a waste of resources. More, if the
OpenID provider is not available, the signature verification would fail and the API would not be able to perform the
request and serve the client. To avoid this (dramatic) situation, an agressive caching mecanism is put in place: if the
well-known URLs or the public key URLs are not available in a timely manner, a previously never expiring cache is used
as a source. Upon each (re)start of the API, the cache is updated if possible.

To facilitate integration with other external systems, a list of clients (section `auth.clients.known`) can optionally
be provided. The client ID found in the JWT token is matched against the instance's main client ID
(`auth.oidc.client_id`) or one of these. If there's no match, the middleware rejects the request with an explicit `HTTP
400` error, signaling the token provided by the client is invalid (with a self-explanatory message). Depending on the
token format, the client ID is taken in from the field `azp`, or `client_id`. If both `azp` and `client_id` are found in
the claims, `client_id` has precedence over `azp`.

Once the signature has been verified, the middleware also verifies that the token is still valid, by checking the claims
field `exp`. This field contains a timestamp in the Epoch format and assumed to be in UTC. Token caching is possible
(though rarely used) by enabling the parameter `auth.oidc.cache_tokens`. When true, the field `jti` (JWT ID, a unique
token ID value) is used for that purpose, as well as the `exp` value (minus a few seconds to allow some slack in the
expired/not-expired decision) for the cache TTL value. If the same token is used and was cached by the API, the
verification process (signature, expiration) is skipped, to allow faster request processing.

Passing these checks, the middleware inspects the potential roles found in the claims, in order to know if the user is
an admin or not. An instance of an `artifactdb.rest.auth.AuthenticatedUser` (or `artifactdb.rest.auth.AdminUser`) is
created, and injected in a context variable for the time of the request. This "user context" variable is used when
querying Elasticsearch to inject authorization information (permissions), avoiding to pass this user across all function
and method calls. By design, if no user is found in this context variable, the Elasticsearch query fails (this, to
prevent any accidental data access, ie. no user could be lead to no permission-based filtering in the query). Once the
request was processed (a response was prepared, ready to return), the middleware reads the user context variable, checks
that the value is the same than the one it previously set, before resetting the context itself. This extra check at the
end ensures there was no accidental manipulation of the context itself during the request, as well as ensure the next
request starts from a fresh, empty context.

This user object contains information such as her `unixID` (taken from `preferred_username`), the resource she's trying
to access (the path), the roles if any, the raw and parsed JWT token. Optionally, the middleware can enrich distribution
lists and Active Directory groups membership, if such information providers are declared in the configuration.

Finally, if no JWT token is found is the HTTP header, the request is considered anonymous. Following the user context
variable requirement, an `artifactdb.rest.auth.AnonymousUser` instance is created and injected in the context. Without
this, all queries would fail. The query engine (`artifactdb.db.elastic.manager.ElasticsearchManager`) inspects the user
type (anonymous, authenticated, admin) to adjust the permission-based filtering rule and return results accordingly (eg.
only publicly readble projects for anonymous users).

[^1]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-bearer-19#page-5
