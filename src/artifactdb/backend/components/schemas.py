from gpapy.db.schema import SchemaClientManager
from artifactdb.backend.components import BackendComponent


class SchemaManager(BackendComponent, SchemaClientManager):

    NAME = "schema_manager"
    FEATURES = ["schemas","validation"]
    DEPENDS_ON = []

    def __init__(self, manager, cfg):
        self.main_cfg = cfg
        SchemaClientManager.__init__(self,self.main_cfg.schema)

