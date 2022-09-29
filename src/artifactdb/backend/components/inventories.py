import json
import re
import logging
from collections import OrderedDict
from datetime import datetime

import boto3

from artifactdb.backend.components import BackendComponent


INPUT_FORMATS = {
    "csv": {
        'CompressionType': 'GZIP',
        "CSV": {
            'FieldDelimiter': ',',
        }
    },
    "json": {
        'CompressionType': 'NONE',
        "JSON": {
            'Type': 'LINES'
        }}
}

OUTPUT_FORMATS = {
    "JSON": {},
}


class InvalidQueryParameter(Exception): pass
class UnknownFormat(Exception): pass
class UnknownSource(Exception): pass
class NoInventoryRecordFound(Exception): pass


class S3InventoryManager(BackendComponent):

    NAME = "s3_inventory"
    FEATURES = ["inventories",]
    DEPENDS_ON = []

    def __init__(self, manager, cfg):
        self.main_cfg = cfg
        self.cfg = self.main_cfg.s3_inventory
        self.bucket_name = self.cfg.inventory_bucket
        self.folder = self.cfg.folder
        if not self.bucket_name or not self.folder:
            raise UnknownSource("Missing configuration for S3 inventories")
        self.access_key = self.cfg.credentials.access_key
        self.secret_key = self.cfg.credentials.secret_key
        self.field_mapping = OrderedDict()
        self.manifest_data = None
        self.s3_client = self.get_client()

    def get_client(self):
        try:
            params = dict(aws_access_key_id=self.access_key,
                          aws_secret_access_key=self.secret_key)
            self.s3_client = boto3.client("s3", **params)
            return self.s3_client
        except Exception as e:
            logging.exception("Error occured while preparing s3 client'{}'".format(e))
            raise

    def get_query_data(self, key, input_format, query=None):
        try:
            input_ser = INPUT_FORMATS.get(input_format)
            if not input_ser:
                raise UnknownFormat("Unsupported input format: {}".format(input_format))
            expression = "SELECT * FROM s3object s"
            if query:
                # identify expressions separated by "AND" or "OR" (case insensitive)
                exprs = re.split(r"\s+(and|or)\s+",query,flags=re.IGNORECASE)
                for i,expr in enumerate(exprs):
                    predicate = list(map(str.strip,re.split(r"(like|=)",expr,flags=re.IGNORECASE)))
                    if len(predicate) == 1:
                        continue  # and/or keyword, we only want the predicates
                    # convert column name into _1 s3select notation
                    predicate[0] = self.get_key_from_field_mapping(predicate[0])
                    expr = " ".join(predicate)
                    exprs[i] = expr
                final_query = " ".join(exprs)
                expression += f" WHERE {final_query}"
                logging.debug("Converted query {} for s3select => {}".format(repr(query),repr(expression)))

            resp = self.s3_client.select_object_content(
                Bucket=self.bucket_name,
                Key=key,
                ExpressionType='SQL',
                Expression=expression,
                InputSerialization=INPUT_FORMATS[input_format],
                OutputSerialization=OUTPUT_FORMATS,
            )
            return resp
        except Exception as e:
            logging.exception("Error occured while fetching query data'{}'".format(e))
            raise

    def prepare_field_mapping(self):
        values = OrderedDict()
        for index, value in enumerate(self.manifest_data[0]['fileSchema'].split(',')):
            key = "_" + str(index + 1)
            values[key] = value.strip()
        self.field_mapping = values

    def get_key_from_field_mapping(self, field):
        for key, value in self.field_mapping.items():
            if value == field:
                return key

    def extract_payload(self, data):

        strjson = ""
        for event in data["Payload"]:
            if "Records" in event and event["Records"]["Payload"]:
                strjson += event["Records"]["Payload"].decode("utf8")
        data = []
        for line in strjson.splitlines():
            data.append(json.loads(line))
        return data

    def prepare_final_result(self, values):
        return [dict((self.field_mapping[key], value) for (key, value) in data.items()) for data in
                values] if values else []

    def get_inventory_project_files(self, date=None, query=None):
        try:
            manifest_file_data = None
            if date and date != 'latest':
                # check date format is correct
                try:
                    datetime.strptime(date, "%Y-%m-%d")
                except ValueError:
                    raise ValueError("Incorrect Date format!! DateFormat-> YYYY-MM-DD")
            paginator = self.s3_client.get_paginator('list_objects')
            response = paginator.paginate(Bucket=self.bucket_name, Prefix=self.folder)
            date = date or 'latest'
            if date == 'latest':
                # get the latest created Manifest file
                results = response.search("sort_by(Contents[?contains(Key,'manifest.json')],&to_string(creationTimestamp))[-1]")
            else:
                # find the manifest file for the given date
                results = response.search("Contents[?contains(Key,'manifest.json') && contains(Key,'{}')]".format(date))
            for result in results:
                if not result:  # could be None, not sure why...
                    continue
                manifest_file_data = self.get_query_data(result.get('Key'), 'json')
            if manifest_file_data:
                self.manifest_data = self.extract_payload(manifest_file_data)
                self.prepare_field_mapping()
                timestamp = int(self.manifest_data[0]['creationTimestamp']) / 1000 # divide timestamp by 1000 to convert from milliseconds to seconds.
                final_data = {
                    "inventory_date": str(datetime.fromtimestamp(timestamp).date()),
                    "results": [],
                }
                for file in self.manifest_data[0]['files']:
                    data = self.get_query_data(file["key"], 'csv', query)
                    final_data["results"].extend(self.prepare_final_result(self.extract_payload(data)))
                return final_data
            else:
                raise NoInventoryRecordFound(f"No inventory records found for date: {date}")
        except Exception as e:
            logging.exception("Error occured while getting project files'{}'".format(e))
            raise
