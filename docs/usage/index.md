# Indexing metadata

TODO:
- describe indexing process
- show different ways to create and register a model
- explain index management endpoints


## Excluding files from indexing

JSON files can be exluded from being indexed using a special file named `.adbignore`. Similar to `.gitignore` for
instance, this optional file contains file paths which should be ignored when preparing indexing of metadata. The paths
are relative to the project and version folder, as this information is usually not known yet at the time of the upload
process. For conveniency, paths can start with or without `/`, the backend will trim that character as required.

Let's consider the following use case where this file comes handy. We're using JSON files to describe metadata, but
image we now have a JSON file also containing data, located in `myexperiment1/myassay2/bigfile.json`. By default, all
JSON files are considered metadata files and will be part of the indexing process. Including such a JSON data would
certainly cause indexing errors, as it would not match any schema, or be even too big to be indexed. Using `.adbignore`
file, we can explicitely exclude that file, the content would be:

```
myexperiment1/myassay2/bigfile.json
```

The resulting `.adbignore` file should be uploaded at the root of the project/version folder (usually meaning the file
should be located on the host at the root of the staging directory, where all files are prepared for upload).

Using this method is currently the only way to be able to use JSON files as data file without having them causing error
during indexing. Another scenario would be to use that file to exclude "real" metadata files explicitely, for instance
if the format is not compatible with revent schema versions, while still keeping these legacy metadata files on the
storage without causing issue.

