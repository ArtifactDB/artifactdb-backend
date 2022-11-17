import os
import logging
import datetime

from artifactdb.backend.components import WrappedBackendComponent
from artifactdb.identifiers.gprn import get_parents, lca, get_lineage
from artifactdb.utils.misc import get_class_from_classpath
from artifactdb.config.utils import init_model
from artifactdb.config.inspectors import InspectorConfig, CoreInspectorConfig



class InspectorError(Exception): pass


class InspectorsManagerComponent(WrappedBackendComponent):

    NAME = "inspectors_manager"
    FEATURES = ["inspectors",]
    DEPENDS_ON = []

    def wrapped(self):
        return InspectorsManager(self.manager,self.main_cfg.inspectors)

    def __getitem__(self, schema_alias):
        return self._wrapped[schema_alias]


class InspectorsManager:

    def __init__(self, manager, inspectors_cfg, internal_meta_folder=".artifactdb"):
        self.manager = manager
        self.inspectors_cfg = inspectors_cfg
        self.internal_meta_folder = internal_meta_folder
        self.inspectors = {}
        for dinspect in self.inspectors_cfg:
            inspect = init_model(InspectorConfig,dinspect)
            if inspect.type == "core":
                klass = get_class_from_classpath(inspect.core.classpath)
                klass.alias = inspect.alias
                if inspect.alias in self.inspectors:
                    raise InpsectorError(f"Inspector {inspect.alias!r} already registered")
                self.inspectors[inspect.alias] = klass(self.manager)
            else:
                raise InspectorError(f"Inspector type {dinspect['type']!r} is not supported")

    def generate_metapath(self, meta):
        return os.path.join(self.internal_meta_folder,meta["path"] + ".json")

    def inspect_s3data(self, s3data, project_id, version):
        """
        Inspect file on S3 based on s3data, and return list of tuple(metapath,meta)
        where `metapath` and a filename for the metadata `meta` to be stored in.
        """
        metas = []
        for alias,inspector in self.inspectors.items():
            logging.debug("Inspecting {s3data['Key']} with {inspector}")
            inspected = inspector.inspect(s3data, project_id, version)
            if inspected:
                # ensure $schema, in case the inspector forgot to put it
                inspected["$schema"] = inspector.schema
                metapath = self.generate_metapath(inspected)
                metas.append((metapath,inspected))

        return metas

    def inspect(self, project_id, version):
        metas = []
        for s3data in self.manager.s3.list_folder(os.path.join(project_id,version)):
            metas.extend(self.inspect_s3data(s3data, project_id, version))
        
        return metas

