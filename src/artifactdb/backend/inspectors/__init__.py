

class InspectorBase(object):

    alias = None  # set by manager

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

