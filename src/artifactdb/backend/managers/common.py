from artifactdb.backend.managers.base import BackendManagerBase
from artifactdb.backend.components.plugins import PluginsManager
from artifactdb.backend.components.sequences import SequenceManager
from artifactdb.backend.components.storages import StorageManager


class ArtifactDBBackendManagerBase(BackendManagerBase):
    
    COMPONENTS = [
        # must always be there for an ArtifactDB API
        {"class": StorageManager, "required": True},
        # Recommended but optionals
        {"class": SequenceManager, "required": False},
        {"class": PluginsManager, "required": False},
    ]



