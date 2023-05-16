

class InspectorBase:

    alias = None  # set by manager
    schema = None

    @property
    def id(self):
        assert self.__class__.schema, "Inspector has no schema assigned, invalid"
        # defaulting to schema name (what if multiple version? not sure it's even possible or make sense)
        return self.__class__.schema.split("/")[0]

    def __init__(self, manager):
        """
        Initialize an inspector from main backend `manager`.
        """
        self.manager = manager

    def inspect(self, content, project_id, version, **kwargs):
        """
        Inspect and return metadata about `content` (usually S3 data coming for a listing).
        `project_id` and `version` are provided for context.
        """
        raise NotImplementedError()

