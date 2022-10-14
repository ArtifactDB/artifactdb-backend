import logging

from artifactdb.db.schema import SchemaClientManager, NoSchemaError
from artifactdb.backend.components import WrappedBackendComponent, managermethod


class SchemaManager(WrappedBackendComponent):

    NAME = "schema_manager"
    FEATURES = ["schemas","validation"]
    DEPENDS_ON = []

    def wrapped(self):
        return SchemaClientManager(self.main_cfg.schema)

    def __getitem__(self, schema_alias):
        return self._wrapped[schema_alias]


#########################
# Backend method mixins #
#########################

@managermethod
def validate_document(self, doc):
    try:
        self.schema_manager.validate(doc)
    except NoSchemaError as e:
        if self.cfg.schema.reject_when_no_schema:
            raise
        logging.warning(e)


@managermethod
def validate_documents(self, docs):
    logging.info(f"Validating {len(docs)} documents")
    for doc in docs:
        self.validate_document(doc)

