# pylint: disable=no-member
import os
import logging
import json
from collections.abc import Iterable

from artifactdb.backend.components import WrappedBackendComponent
from artifactdb.backend.utils import generate_ignore_file_key
from artifactdb.utils.misc import get_class_from_classpath
from artifactdb.config.utils import init_model
from artifactdb.config.inspectors import InspectorConfig



class InspectorError(Exception): pass


class InspectorsManagerComponent(WrappedBackendComponent):

    NAME = "inspectors_manager"
    FEATURES = ["inspectors",]
    DEPENDS_ON = []

    def wrapped(self):
        return InspectorsManager(self.manager,self.main_cfg.inspectors)


class InspectorsManager:

    def __init__(self, manager, inspectors_cfg, internal_meta_folder=".artifactdb", split_by_inspector=True):
        self.manager = manager
        self.inspectors_cfg = inspectors_cfg
        self.internal_meta_folder = internal_meta_folder
        self.split_by_inspector = split_by_inspector
        self.inspectors = {}
        for dinspect in self.inspectors_cfg:
            inspect = init_model(InspectorConfig,dinspect)
            if inspect.type == "core":
                klass = get_class_from_classpath(inspect.core.classpath)
                klass.alias = inspect.alias
                if inspect.alias in self.inspectors:
                    raise InspectorError(f"Inspector {inspect.alias!r} already registered")
                self.inspectors[inspect.alias] = klass
            else:
                raise InspectorError(f"Inspector type {dinspect['type']!r} is not supported")

    def generate_metapath(self, inspector, meta, project_id, version):
        elems = [project_id, version, self.internal_meta_folder]
        if self.split_by_inspector:
            elems.append(inspector.id)
        elems.append(meta["path"] + ".json")
        return os.path.join(*elems)

    def inspect_s3data(self, inspectors, s3data, project_id, version):
        """
        Inspect file on S3 based on s3data, and return list of tuple(metapath,meta)
        where `metapath` and a filename for the metadata `meta` to be stored in.
        """
        metas = []
        for inspector in inspectors:
            logging.debug(f"Inspecting {s3data['Key']} with {inspector}")
            inspected = inspector.inspect(s3data, project_id, version)
            if inspected:
                if isinstance(inspected,dict) or not isinstance(inspected, Iterable):
                    inspected = [inspected]
                # iterate, modify in-place
                for one in inspected:
                    # ensure $schema, in case the inspector forgot to put it
                    one["$schema"] = inspector.schema
                    metapath = self.generate_metapath(inspector, one, project_id, version)
                    metas.append((metapath,one))

        return metas

    def inspect(self, project_id, version):
        metas = []
        # if a json file is in the ignore list, it means it's a data file, not a metadata file
        # we keep it for inspection
        ignored = self.manager.s3.get_ignore_list(project_id, version)
        # ignore the ignore file itself...
        ignore_key = generate_ignore_file_key(project_id, version)
        # instantiate inspectors for that round of inspection, allowing their cache to stay valid for the whole run for
        # this project/version
        inspectors = {klass(self.manager) for klass in self.inspectors.values()}
        for s3data in self.manager.s3.list_folder(os.path.join(project_id,version)):
            # do not inspect generated metadata files in ..artifactdb folder (internal metadata folder)
            # nor json files which are metadata files (very unlikely to have a mix of the 2 cases though)
            if (
                s3data["Key"].startswith(os.path.join(project_id,version,self.internal_meta_folder)) \
                or (s3data["Key"].endswith(".json") and s3data["Key"] not in ignored) \
                or s3data["Key"].startswith(ignore_key)
            ):
                continue  # it's a previously inspected meta or an uploaded metadata

            metas.extend(self.inspect_s3data(inspectors, s3data, project_id, version))
        logging.debug(f"While inspecting, generated {len(metas)} metadata file(s)")
        for metapath,meta in metas:
            logging.debug(f"Uploading {metapath}")
            self.manager.s3.upload(metapath,json.dumps(meta,indent=2),content_type="application/json")

        return metas

