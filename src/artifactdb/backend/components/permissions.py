import logging
from typing import List, Union, Optional

from pydantic import BaseModel, Field
from typing_extensions import Literal


class PermissionsError(Exception):
    pass

class NoPermissionFoundError(Exception):
    pass


class Permissions(BaseModel):
    """
    Permissions model stored in storage and index.
    If none of the fields are set (all remain None), default
    permissions are applied (defined in configuration)
    """
    scope: Literal["global","project","version"] = Field(None,
                description="Specify the level on which permissions are applied. " + \
                            "Permisions scope 'project' declares default permissions for any " + \
                            "versions to come, while 'version' declares permissions specific " + \
                            "to the version being marked as completed. 'global' permissions " + \
                            "can be defined at bucket-level and would valid for any " + \
                            "project/version without registered permissions.")

    owners: Union[List[str], str] = Field(None,
                description="List (comma-separated string) of users who have read & write permissions")
    viewers: Optional[Union[List[str], str]] = Field(None,
                description="List (comma-separated string) of users who have read-only permissions")
    read_access: Optional[Literal["public","authenticated","viewers","owners","none"]] = Field(None,
                description="Gives read-only access to anyone ('public'), 'authenticated' users, or " + \
                            "according to 'permissions' (default if not specificed) declared in " + \
                            "'viewers' field")
    write_access: Optional[Literal["public","authenticated","viewers","owners","none"]] = Field(None,
                decription="Same as 'read_access' but for write operations. If 'permissions' (default), " + \
                           "write access taken from 'owners' field")

    class Config:
        schema_extra = {
            "example": {
                "owners" : ["user1","user2"],
                "viewers": "research-d@gene.com",
                "read_access": "viewers",
                "write_access": "owners",
            }
        }

    def to_dict(self):
        # mimick ElasticSearch DSL, this is kind of everywhere in the code
        perms = self.dict(exclude_none=True)
        return perms


class PermissionValidator:

    def is_valid(self, permission):
        raise NotImplementedError("Please implement 'is_valid' method.")


class PermissionsBaseWrapper:
    """
    Wrapper over Permissions dealing with user input
    """

    permissions_model = None

    def __init__(self, permissions_dict):
        """
        Initialize a permissions object from dict, sanitizing types
        (eg. "owners" can be a string of comma-seperated user, or a list of string)
        """
        assert self.__class__.permissions_model, "Permissions model class not set"
        normalized = {}
        # should always be a list
        for field in ("owners","viewers"):
            # note collab are optional, but also owners (data is strictly administer by a admin,
            # and no user owns/manage the data
            if field in permissions_dict:
                normalized[field] = self.normalize(permissions_dict[field])
        permissions_dict.update(normalized)  # overwrite with normalized values
        # pylint: disable=not-callable  # was asserted before
        self.permissions = self.__class__.permissions_model(**permissions_dict)

    def normalize(self, value):
        if isinstance(value,str):
            value = list(map(str.strip, value.split(',')))
        assert isinstance(value,list), "Can't normalize value {}".format(repr(value))
        return value

    @classmethod
    def propagate_default_permissions(cls, default_permissions):
        """
        Dynamically set default permissions in model
        """
        for k,v in default_permissions.items():
            assert k in cls.permissions_model.__fields__, "Default permissions contain invalid key '{}'".format(k)
            cls.permissions_model.__fields__[k].default = v
        # also in __field__defaults__, though it doesn't have an impact in setting default values. just for consistency
        cls.permissions_model.__field__defaults__ = default_permissions

    def __repr__(self):
        return "<{}.{}: {}>".format(self.__module__,self.__class__.__name__,self.to_dict())

    def project_specific(self):
        """
        Return true if permissions are project-specific
        """
        return self.permissions.scope == "project"

    def version_specific(self):
        """
        Return true if permissions are version-specific
        """
        return self.permissions.scope == "version"

    def to_dict(self):
        return self.permissions.to_dict()


class StandardPermissionsWrapper(PermissionsBaseWrapper):

    permissions_model = Permissions


class PermissionManagerBase:

    def __init__(self, storage_provider, es_manager, permissions_wrapper=StandardPermissionsWrapper,
                 default_permissions=None, validators=()):
        self.storage_provider = storage_provider
        self.es = es_manager
        self.permissions_wrapper = permissions_wrapper
        self.default_permissions = default_permissions
        self.validators = validators
        for v in validators:
            if not isinstance(v, PermissionValidator):
                raise PermissionsError("At least one validator is not the instance of PermissionValidator.")
        # set default field values in model, from default permissions
        if self.default_permissions:
            self.permissions_wrapper.propagate_default_permissions(self.default_permissions)

    @property
    def s3(self):
        return self.storage_provider()


class InheritedPermissionManager(PermissionManagerBase):
    """
    "permissions" can be passed to set authorizations, for a given project or project/version,

    If default is kept, permissions are inherited.
    1) from the version (if previously set there, in case of re-indexing of an existing version), or
    2) from the project itself.

    Example 1: a new version of projec is indexed, permissions are not specified, they will be inherited
        by default from the permission set at project level (defined in the "internal metadata" folder on S3).
        If no such permissions exist at project level, an error is raised.
    Example 2: an existing version is reindexed, permissions are not specified. Permissions are first taken
        from a permission set at version level, and if non-existent, then taken from permissions are project
        level.
    Example 3: a new version is indexed, permission are specified with "scope=version". This means permissions
        are valid only for this version. If a subsequent project-level permissions are specified in another
        indexing job, these version-specific permissions are kept, unless force=True, which in this case
        will delete any version-specific permissions so they're replaced by the project-level one.

    Note: there's currently no support for file-specific permissions.

    Ex:
    permissions = {
        "owners" : ["user1","user2"],
        "viewers": ["another1"],
        "scope": "project|version"
    }
    """

    NAME = "permissions_manager"
    FEATURES = ["permissions",]
    DEPENDS_ON = ["storage_manager",]

    def __init__(self, manager, cfg):
        PermissionManagerBase.__init__(self,
            manager.storage_manager.get_storage,
            manager.es,
            default_permissions=cfg.permissions.default_permissions,
        )

    def register_permissions(self, project_id, version=None, permissions=None):
        """
        Register permissions for given project. 'permissions' can include 'scope'
        information to decide whether permissions should be applied at project or
        version level. This scope has precedence over 'version' parameter.
        If no scope is declared in 'permissions', then if version is specified,
        permissions are version-specific, otherwise they are project-specific.
        (in other words, if version="abc123" and permissions.scope="project",
        permissions are project-specific. Precedence...)

        `permissions` can be a partial definition. For instance, it could include
        only the `owners` information. In order to obtain the final permissions
        definition, `resolve_permissions()` is called for given project/version.
        This will ensure we keep as much previous information as possible, namely,
        if permissions exist for project/version, partial passed permissions are
        merged on top of them (see GDB-301).
        """
        # version is optional, but not permissions, but I wanna keep the same signature
        assert permissions, "Specify permissions to register"
        assert isinstance(permissions,dict), "Expected dict for passed permissions"
        # check if existing permissions, if so, merge passed ones on top of existing
        existing = {}
        try:
            obj = self.resolve_permissions(project_id,version)
            existing = obj.to_dict()
        except NoPermissionFoundError:
            pass
        existing.update(permissions)  # replace with what's explicitly passed
        # at this point, `existing` may still be incomplete, either because there was no permissions
        # before (empty dict) and the existing permissions are partial.
        # use wrapper, to ensure we set all possible fields and we store complete permissions definition
        perm_obj = self.permissions_wrapper(existing)
        if perm_obj.project_specific():
            version_arg = None
        else:
            version_arg = version
        if perm_obj.version_specific() and version is None:
            raise PermissionsError("Permissions scope is 'version' but no version specified")

        self.s3.register_permissions(project_id,version_arg,perm_obj)

        return perm_obj

    def get_permissions(self, project_id=None, version=None):
        """
        Return explicit permissions (if any) for the project_id/version.
        Note: there's no resolution, eg. no permission for given version,
        will not explore further up to project-level. See resolve_permissions()
        for this behavior.
        """
        perm_obj = None
        permissions = self.s3.get_permissions(project_id,version)
        if permissions:
            perm_obj = self.permissions_wrapper(permissions)

        return perm_obj

    def resolve_permissions(self, project_id, version, scope=None):
        """
        Given a 'project_id'/'version', find permissions that should apply to files
        within the version. That is, if permissions exists for given 'version',
        they have precedence over permissions existing at project level.
        Othewise, permissions at project level are considered.

        If 'scope' is define, it has precedence of 'version', see register_permissions().

        If no permissions could be found, an error is raised.
        """
        perm_obj = None

        if scope and scope == "project":
            version = None # just ignore the version parameter

        # first try specific permissions for given version (not inherited from project's ones)
        perm_obj = self.get_permissions(project_id,version)
        if perm_obj:
            logging.info("Found version-specific permissions from {}/{}".format(project_id,version))
        else:
            # second pass, project-level
            perm_obj = self.get_permissions(project_id)
            if perm_obj:
                logging.info("Found project-specific permissions for {}".format(project_id))
            else:
                # last pass, global
                perm_obj = self.get_permissions()
                if perm_obj:
                    logging.info("Found global permissions for {}".format(project_id))

        if perm_obj is None:
            # couldn't find any suitable permissions, that's not good
            raise NoPermissionFoundError("No permissions found for {}/{}".format(project_id,version))

        return perm_obj

    def delete_permissions(self, project_id=None, version=None):
        return self.s3.delete_permissions(project_id,version)

    def complete_permissions(self, project_id, version, pobj):
        try:
            existing = self.resolve_permissions(project_id,version)
            # only override existing perms attributes explicitly set from new pobj
            # and not the ones coming from default perms propagation (see GDB-301)
            for field in pobj.__fields_set__:
                # GDB-337: None values get dropped by the pydantic models resulting in not stored None values
                # (and original value is kept intact), so we make sure to convert to
                # an empty list (which is a valid value too)
                if field in ("owners","viewers") and getattr(pobj,field) is None:
                    setattr(pobj,field,[])
                setattr(existing.permissions,field,getattr(pobj,field))
            return existing
        except NoPermissionFoundError:
            return pobj

    def is_valid(self, permission: Permissions):
        for validator in self.validators:
            if not validator.is_valid(permission):
                return False

        return True
