# Fetching metadata

## Getting a document by its ID

Fetching metadata implies to look up a specific document by its ID. In the context of ArtifactDB, one document
represents one single metadata document, the identifier is an [ArtifactDB ID](../design/identifiers), found under all
indexed document in `_extra.id` field. Getting a document by its ID can be achieved using the endpoint
`/files/{id}/metadata`. The response is a JSON object representing the indexed document, usually equivalent to the JSON
metadata stored on the the storage, with the addition of the [`_extra`](_extra) key.

## Getting documents belonging to a specific project and version

Other endpoints allow to fetch metadata, eg. for a given project and version using
`/projects/{project_id/version/{version}/metadata`, or metadata for all versions within a specific project, with
`/projects/{project_id}/metadata`. Strictly speaking, this doesn't correspond to fetching metadata, as multiple
documents can be returned. Behind the scene, these endpoints perform a search, filtering by project and version. The
consequence is the API response is the same as what the [`/search` endpoint](search) would return. This includes the
usage of scrolls when a project/version would contain a lot of documents, requiring to "consume" that scroll entirely to
make sure all documents are returned.

