import os

from . import InspectorBase

class ListerInspector(InspectorBase):

    schema = "entry.minimal/v1.json"
    schema_def = {
        "$schema": "http://json-schema.org/draft-07/schema",
        "$id": "entry.minimal.v1",
        "type": "object",
        "title": "Minimal entry",
        "description": "Minimalist schema to allow uploading files without metadata",
        "properties": {
            "path": {
                "type": "string",
                "description": "File path relative to the project/version folder",
            }
        }
    }

    def inspect(self, s3data, project_id, version, **kwargs):
        """
        Return metadata for given `s3data` (coming from an s3 listing).
        `project_id` and `version` are provided for context.
        """
        elems = s3data["Key"].split("/")
        # S3 lists from the root of the bucket, we need related to the project/version
        assert elems.pop(0) == project_id
        assert elems.pop(0) == version
        key = os.path.join(*elems)

        return {
            "path": key,
        }

