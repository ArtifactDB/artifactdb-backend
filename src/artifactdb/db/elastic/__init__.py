from elasticsearch.exceptions import TransportError, NotFoundError

# where to look at user info for auth
AUTH_FIELDS = {"_extra.permissions.owners","_extra.permissions.viewers"}

# Default valid scroll time
DEFAULT_SCROLL = "2m" # 2 minutes

# Default batch size (eg. when bulk indexing)
DEFAULT_BATCH_SIZE = 1000


class NotAllowedException(Exception): pass
class NoMoreResultsException(Exception): pass
class DataInconsistencyException(Exception): pass
class ModelException(Exception): pass

class SnapshotError(Exception): pass
class SnapshotInProgress(SnapshotError): pass
class SnapshotFailure(SnapshotError): pass
class SnapshotAlreadyExists(SnapshotError): pass

