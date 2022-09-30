from gpapy.db.schema import SchemaClientManager
from artifactdb.backend.components import WrappedBackendComponent


class SchemaManager(WrappedBackendComponent):

    NAME = "schema_manager"
    FEATURES = ["schemas","validation"]
    DEPENDS_ON = []

    def wrapped(self):
        return SchemaClientManager(self.main_cfg.schema)

