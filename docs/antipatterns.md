# Patterns and Anti-Patterns

ArtifactDB relies on AWS S3 (storage) and Elasticsearch (indexing engine). The backend runs asynchronous tasks, even if triggered
from the REST API (eg. reindexing a project). Considering these three core aspects, here are some considerations whether to choose
to use ArtifactDB (or not):

- AWS S3 is cheap, highly durable and available. The size limit for a given file is 5TB. S3 is slower than a local disk,
  or even a local network drive in most cases, though. If a use case involves heavy reading, a cache layer might be
  necessary.
- The REST API itself doesn't handle the downloads or uploads of data files, but rather delegates that to S3 itself,
  through the usage of pre-signed URLs, or by providing STS credentials, to benefit from accessing S3 with standard AWS
  SDK. The bandwidth is thus delegated to AWS S3 itself.
- Elasticsearch is a distributed indexing engine. It thrives at searching and fetching documents by keyword or full
  text, but can be limiting when it comes to analytical queries compared to a RDBMS. Aggregations are possible,
  ArtifactDB exposes an endpoint for that purpose, but more advanced queries may required an additional storage system.
  Though ArtifactDB uses distributed lock and SQL sequences to provision project identifiers and versions, Elasticsearch
  itself is not transactional, it's an eventual consistency system (reading what's just been written may not be the
  same, but eventually will). The size of a document, that is the size of a given metadata file, cannot exceed 10MB on
  AWS.  The number of documents can be in the order of tens of billions, as Elasticsearch can scale out easily as more
  compute, storage and money is thrown at it... 
- Indexing metadata is asynchronous, which allows the REST API to stay responsive as it delegates the task to the
  backend. This approach is usually fine but in some context, again usually transactional, where a response is required
  as soon as the request was made, for instance as a confirmation or validation, asynchronicity might be a problem.



