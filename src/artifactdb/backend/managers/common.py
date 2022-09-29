# pylint: disable=no-member  # self.permissions_manager injected during build()
# pylint: disable=unused-argument  # pass docs for potential usage in other scenario
import logging

from artifactdb.backend.managers.base import BackendManagerBase
from artifactdb.backend.components.plugins import PluginsManager
from artifactdb.backend.components.sequences import SequenceManager
from artifactdb.backend.components.storages import StorageManager
from artifactdb.backend.components.indexers import BackendElasticManager
from artifactdb.backend.components.permissions import InheritedPermissionManager, NoPermissionFoundError


class ArtifactDBBackendManagerBase(BackendManagerBase):

    COMPONENTS = [
        # must always be there for an ArtifactDB API
        {"class": StorageManager, "required": True},
        {"class": BackendElasticManager, "required": True},
        {"class": InheritedPermissionManager, "required": True},
        # Recommended but optionals
        {"class": SequenceManager, "required": False},
        {"class": PluginsManager, "required": False},
    ]

    # TODO: eg. determine_permissions() and all permissions related methods could be part of the
    # artifactdb.backend.components.permissions component itself, patching/mixin the backend manager

    def determine_permissions(self, docs, project_id, version, permissions):
        """
        Given arguments, return a PermissionsBase object that should be applied
        """
        # docs: by default we're just looking for either explicitelt passed permissions
        # or permissions found at project or project/version level. "docs" is still
        # part of the signature in case another logic needs to be implemented in a subclass
        if permissions:
            # explicit permissions were passed, store them
            logging.info("Register explicit permissions passed for {}/{}: {}".format(project_id,version,permissions))
            self.permissions_manager.register_permissions(project_id,version,permissions)
        # at that point, we should be able to fetch proper permissions from S3
        pobj = None
        try:
            pobj = self.permissions_manager.resolve_permissions(project_id,version)
            logging.info("For {}/{}, found permissions {}".format(project_id,version,pobj))
        except NoPermissionFoundError:
            if self.cfg.permissions.mandatory:
                if self.cfg.permissions.default_permissions:
                    pobj = self.permissions_manager.register_permissions(project_id,version,permissions)
                    logging.info("For {}/{}, applying default permissions: {}".format(project_id,version,pobj))
                    return pobj
                else:
                    raise
            else:
                logging.warning("No permission found for {}/{} ".format(project_id,version) +
                                "but permissions not mandatory (per config). " +
                                "If any, permissions will be removed.")
        return pobj

    def apply_permissions(self, docs, project_id, version, permissions):
        """
        Stores permissions on S3 and apply them on docs. If permissions
        are inherited (no specific permissions passed), they aren't stored
        but existing permissions are loaded from S3 and applied to docs.
        """
        pobj = self.determine_permissions(docs,project_id,version,permissions)
        # now enrich each document with what we found (in-place)
        for doc in docs:
            self.apply_permissions_to_doc(doc,pobj)

    def apply_permissions_to_doc(self, doc, pobj):
        if pobj:
            doc["_extra"]["permissions"] = pobj.to_dict()
        else:
            # setting to None will replace field's content with None, because
            # popping the field out or setting it to {} doesn't work: we're running
            # bulk upserts that would just merge content, ie. preserve existing field content)
            # (note: lucene/ES doesn't support field deletion per se, doc would need
            # to be deleted and re-created. Could be an option in the future if this
            # thing happens somewhere else.)
            doc["_extra"]["permissions"] = None

