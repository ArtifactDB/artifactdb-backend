import requests

class BulkIndexException(Exception): pass

RETRYABLE_EXCEPTIONS = (
    requests.exceptions.ConnectionError,
    BulkIndexException
)

