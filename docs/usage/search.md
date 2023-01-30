# Searching artifacts

All fields (99.9% of them) declared in schemas are indexed in Elasticsearch and are searchable. The `/search` endpoint
exposes the [query
string](https://www.elastic.co/guide/en/elasticsearch/reference/7.4/query-dsl-query-string-query.html) syntax of
Elasticsearch and can be used to search and filter data, using the `q` parameter. The `fields` parameter can be used to
filter down only the fields of interest in a result, for performance reasons for instance.

## Sorting results

The `sort` parameter can be used sort the results on specific fields, in ascending or descending order. Most fields are
indexed using `keyword`, which allows sorting and aggregations, an error is raised though when trying to do the
operations on fields with type `text` for instance.

## Scrolling results

In order to keep the API responsive and performant, the API will serve a “scroll” when there are too many results. This
scroll can be “consumed” to fetch all results, page by page, similarly to cursors usually found in SQL databases and
clients. Once fully consumed, an empty list will be returned with a 404 error. If consuming the scroll again, a 410 error
is returned stating the scroll has expired because it reached the end. That said, scrolls also have a TTL, a few
minutes, so if the scroll isn’t consumed for at least one page within that delay, it will expire as well producing that
same 410 error.

Scroll information, if any, can be found in the key next of a search response, as well as in the headers `link` with the
format `<scroll path>; rel=more`.

## Requesting artifacts from latest versions

The parameter `latest=true` can be used to request from the REST API to return, for any given artifact belonging to a
project, only the latest version available. This is dynamically determined at query time, using an aggregation query,
which induces limitations such as not being able to sort the results when that flag is in use. Another consequence (that
could qualify as a bug...) is the `total` field content is inaccurate and should not be relied on[^1].

## Examples

TODO: examples, double quotes, tokenized, bool AND/OR/NOT


## FAQ

- *What if I search a field that does not exist and is not indexed?*

- *I don't like scrolls, is there a way to avoid them?*

- *My query gives strange results, why?*


[^1]: The current implementation will change in the future to overcome these limitations.
