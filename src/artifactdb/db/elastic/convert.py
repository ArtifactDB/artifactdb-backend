# pylint: disable=dangerous-default-value  # some args are enriched in-place by design
import logging
import sys
import datetime
import copy

from artifactdb.utils.misc import merge_struct

# select appropriate data type of ES models
DATATYPES = {
    'string': "Keyword",
    'integer': "Integer",
    'object': "Object",
    'enum': "Keyword",
    'number': "Float",
    'text': "Text",
    'keyword': "Keyword",
    'short': "Short",
    'boolean': "Boolean",
    'date-time': "Date",
    'long': "Long",
    'double': "Double",
}


class EsModelScript:

    def __init__(self, client, output_file, types=None, merge=False, class_name=None, clear_cache=True):
        """
        - generate python model based on a schema `client` instance, 
        - writes the result in `output_file`.
        - `types` can be used to filter down to a subset of types available in the `client`, otherwise all are
          considered.
        - `merge` is used when base schemas defines base fields, which are then enriched by another schema it derived
          from, resulting in merging the common fields content together.
        - `class_name` can be used to specify the base class name in the generated python code ("ArtifactDBModel" is
          used othewise.
        - `clear_cache` removes any previous cached entries from the schema client cache itself (recommended).

        """
        self.inner_docs = {}
        self.inner_doc_text = ""
        self.client = client
        self.output_file = output_file
        self.types = [{'name': name} for name in types] if types else []
        self.merge = merge
        self.class_name = class_name or "ArtifactDBModel"
        if clear_cache:
            self.client.cache.clear()

    def fetch_schemas(self):
        """
        Using a artifactdb.db.schema.SchemaClient, fetch and return
        all available schemas
        """
        schemas = []
        # explore types > versions > schemas
        raw_types = self.client.get_types()
        assert raw_types, f"Schema configuration error for client {self.client.alias}: couldn't find schemas"
        types = [elem["name"] for elem in raw_types]
        logging.info(f"Found the following types: {types}")
        for one_type in types:
            raw_versions = self.client.get_versions(one_type)
            assert raw_versions, "No version found for {}".format(one_type)
            versions = [elem["name"] for elem in raw_versions]
            for one_version in versions:
                logging.info(f"Fetching {one_type}/{one_version}")
                schema = self.client.get_schema(one_type, one_version)
                assert schema, f"No schema found for '{one_type}/{one_version}'"
                schemas.append(schema)
        return schemas

    def parse_schemas(self, schemas):
        """
        Prepare dict with schema properties
        """
        parsed_struct = {}
        for schema in schemas:
            prepared = self.prepare_object_field(schema)
            if self.merge:
                merge_struct(copy.deepcopy(prepared),parsed_struct)
            else:
                parsed_struct.update(prepared)
            if schema.get("allOf"):
                for each in schema.get('allOf'):
                    prepared = self.prepare_object_field(each)
                    if self.merge:
                        merge_struct(copy.deepcopy(prepared),parsed_struct)
                    else:
                        parsed_struct.update(prepared)
        return parsed_struct

    @staticmethod
    def check_required(name, data):  # pylint: disable=unused-argument  # soon dead code...
        """
        Check whether the property is required or not.
        """
        # always return False: schema may say required, but if fields from
        # different schemas are combined at root, the required doesn't apply for
        # all schemas
        return False
        #if data.get('required') and name in data["required"]:
        #    return True
        #return False

    @staticmethod
    def extract_elasticsearch_property(value):
        es_val = {
            'index': True,
            'dynamic': 'strict',
            'type': None
        }
        if value.get('_elasticsearch'):
            es_val.update(value['_elasticsearch'])
        return es_val

    @staticmethod
    def guess_field_type(key, value, es_val):
        key_type = value.get('format', value.get('type'))
        if es_val['type'] is not None:
            key_type = es_val['type']
        if not key_type:
            # try to guess default type if none explicitly found
            if value.get("properties"):
                key_type = "object"  # defaulting to object
            elif value.get("items"):
                key_type = "array"

        if not key_type:
            if not value.get('enum') and not value.get("const") and key != "_elasticsearch":
                raise ValueError(f"type is missing, Invalid property:: {key}")
        return key_type

    def prepare_object_field_value(self, param, key, value, es_val):
        if self.additional_all_of_properties(value).get('_elasticsearch'):
            es_val.update(self.additional_all_of_properties(value).get('_elasticsearch'))
        return {
            'required': self.check_required(key, param),
            'fields': self.prepare_object_field(value),
            'index': es_val['index'],
            'dynamic': es_val['dynamic']
        }

    def prepare_field(self, schema, key, field_type, index,es_val):
        val = {
            'field_type': DATATYPES[field_type],
            'required': self.check_required(key, schema),
            'index': index,
            'es_val':es_val
        }
        return val

    def prepare_new_properties(self, additional_properties, properties):
        # need to unpack both properties to give priority to actual param properties, it first considers param properties
        # priority consider right to left
        if self.merge:
            merge_struct(copy.deepcopy(properties),additional_properties)
            new_properties = additional_properties
        else:
            new_properties = {**additional_properties, **properties}
        return new_properties

    def prepare_conditional_properties(self, properties, original_properties={}):
        """
        Extract properties found in "properties" as well as all other properties
        found in conditional statements (then/else). `original_properties` can be
        passed as way to keep these properties in case the same are found in conditional
        ones (originals have precedence)
        """
        additional_properties = {}
        if properties.get('properties'):
            additional_properties.update(
                self.prepare_new_properties(properties.get('properties'),
                                            original_properties.get('properties',{})))
        if properties.get('then'):

            if properties.get('then').get('_elasticsearch'):
                additional_properties['_elasticsearch'] = properties.get('then').get('_elasticsearch')
            if properties.get('then').get('properties'):
                additional_properties.update(
                    self.prepare_new_properties(properties.get('then').get('properties'),
                                                original_properties.get('properties',{})))
            if properties.get('then').get('allOf'):  # if ref properties found in then condition
                additional_properties.update(
                    self.prepare_new_properties(properties.get('then').get('allOf')[0].get('properties'),
                                                original_properties.get('properties',{})))
        if properties.get('else'):
            if properties.get('else').get('_elasticsearch'):
                additional_properties['_elasticsearch'] = properties.get('else').get('_elasticsearch')
            if properties.get('else').get('properties'):
                additional_properties.update(
                    self.prepare_new_properties(properties.get('else').get('properties'),
                                                original_properties.get('properties',{})))
            if properties.get('else').get('allOf'):  # if ref properties found in then condition
                additional_properties.update(
                    self.prepare_new_properties(properties.get('else ').get('allOf')[0].get('properties').items(),
                                                original_properties.get('properties',{})))
        return additional_properties

    def additional_all_of_properties(self, schema):
        additional_properties = {}
        for all_of in schema.get('allOf', []):
            if not schema.get('properties'):
                return all_of
            additional_properties.update(
                self.prepare_conditional_properties(all_of, schema))
        return additional_properties

    def prepare_object_field(self, param):
        data = {}
        additional_prop = self.additional_all_of_properties(param)
        if param.get('properties'):
            param.get('properties').update(additional_prop)
        else:
            param['properties'] = additional_prop
        # if condition at root level of the field (not in allof)
        conditional_prop = self.prepare_conditional_properties(param)
        param.get('properties').update(conditional_prop)
        param['properties'].pop("_elasticsearch", None)
        for key, value in param['properties'].items():
            es_val = self.extract_elasticsearch_property(value)
            index = es_val['index']
            field_prop = None

            if value.get('enum'):  # Consider ENUM field as a Keyword
                field_prop = self.prepare_field(param, key, 'keyword', index,es_val)

            key_type = self.guess_field_type(key, value, es_val)
            if key_type:
                # prepare field for fields that are not type of object, array, list
                if key_type not in ('object', 'array') and not isinstance(key_type, list):
                    field_prop = self.prepare_field(param, key, key_type, index,es_val)

                if key_type == 'object':  # prepare object field -> Recursive loop
                    field_prop = self.prepare_object_field_value(param, key, value, es_val)

                if key_type == 'array':
                    if value.get('items'):  # check if value contains items otherwise needs to ignore
                        es_item_val = self.extract_elasticsearch_property(value.get('items'))
                        if es_val['dynamic'] != 'strict':
                            es_item_val['dynamic'] = es_val['dynamic']
                        index = es_item_val['index']

                        if value.get('items').get('enum'):  # Consider ENUM field as a Keyword
                            field_prop = self.prepare_field(param, key, 'keyword', index,es_val)

                        field_type = self.guess_field_type(key, value.get('items'), es_item_val)
                        if field_type not in ('object', 'array') and not isinstance(field_type, list):
                            field_prop = self.prepare_field(param, key, field_type, index,es_val)

                        if field_type == 'object':  # prepare object field -> Recursive loop
                            field_prop = self.prepare_object_field_value(param, key, value.get('items'), es_item_val)
                    else:
                        field_prop = self.prepare_field(param, key, "keyword", index,es_val)

                if isinstance(key_type, list):
                    if "object" in key_type and value.get('items'):
                        field = self.prepare_object_field_value(param, key, value.get('items'), es_val)
                    else:
                        # Any other type except Object
                        # remove "null" type as it's not supported by ES anyways.
                        valtypes = [_ for _ in value["type"] if _ != 'null']
                        # this is an important decision here: the first elem in the list
                        # has precedence over the others. Good to know...
                        field = self.prepare_field(param, key, valtypes[0], index,es_val)
                    field_prop = field
            data.update({key: field_prop})
        return data

    def generate_code(self, parsed_struct):
        # Note on below code in f-string: curly brackets for eg. dict require them to be espaced with {{
        models = {
            "import_statements": """
from elasticsearch_dsl import (
    Document, InnerDoc, Text, Nested, Completion, Keyword,
    Object, MetaField, analyzer, tokenizer, analysis, Field,
    Short, Float, Long, Double, Boolean, Integer, Date)

from artifactdb.db.elastic.models import (
    english_analyzer, Alias, ExtraInfoBase,
    ArtifactDBDocumentBase)

""",
            "innerdoc": "",
            "main_class": f"""

class {self.class_name}(ArtifactDBDocumentBase):\n
    class Meta:
        dynamic = MetaField('strict')
    class Index:
        name = None
        settings = {{"query": {{"default_field": "*,all"}}}}\n
    _extra = Object(ExtraInfoBase)
""",
            "invalid_fields": ""
        }
        invalid_fields = []
        for each in sorted(parsed_struct):
            if each.startswith("$"):
                logging.info(f"Skipping field {each}, invalid")
                invalid_fields.append(each)
                continue
            if parsed_struct.get(each).get("field_type"):
                models["main_class"] += "    " + self.prepare_field_text(parsed_struct, each) + "\n"
            else:
                model_name = each.replace('_', '').capitalize() + '_InnerDoc'
                models["innerdoc"] += self.prepare_innerdoc_model(parsed_struct.get(each), each, model_name)
                field = each + " = Object" + "(" + model_name + ")"
                if not parsed_struct.get(each).get('fields') or not parsed_struct.get(each).get('index'):
                    field = each + " = Object" + "(" + model_name + ", enabled=False)"
                elif parsed_struct.get(each).get('required'):
                    field = each + " = Object" + "(" + model_name + ", required=True)"
                models["main_class"] += "    " + field + "\n"

        models['invalid_fields'] += self.prepare_invalid_fields(invalid_fields, parsed_struct, self.class_name)
        return models

    @staticmethod
    def prepare_field_text(parsed_struct, key):
        field = key + " = " + parsed_struct.get(key).get("field_type") + "()"
        if parsed_struct.get(key).get("field_type") == "Object":
            field = key + " = " + parsed_struct.get(key).get("field_type") + "(enabled=False)"
        elif not parsed_struct.get(key).get('index'):
            field = key + " = " + parsed_struct.get(key).get("field_type") + "(index=False)"
        elif parsed_struct.get(key).get('required'):
            field = key + " = " + parsed_struct.get(key).get("field_type") + "(required=True)"
        return field

    def check_field_properties(self,prop, inner_doc_field,field):
        if inner_doc_field != field:
            logging.info(f"Found duplicate properties with different values. '{prop}")

    def check_model_exist(self, model_name, fields):
        # check the model already created or not, if already created check for it's properties if properties are different
        # need to create new model
        if model_name in self.inner_docs:
            if sorted(self.inner_docs[model_name].keys()) == sorted(fields.keys()):
                for field in fields:
                    for inner_doc_field in self.inner_docs[model_name]:
                        if inner_doc_field == field:
                            self.check_field_properties(field, self.inner_docs[model_name][inner_doc_field],fields[field])
                return True
            return -1
        return False

    @staticmethod
    def prepare_invalid_fields(invalid_fields, parsed_struct, model_name):
        doc = ""
        for invalid_field in invalid_fields:
            field = parsed_struct.get(invalid_field).get("field_type") + "()"
            if not parsed_struct.get(invalid_field).get('index'):
                field = parsed_struct.get(invalid_field).get("field_type") + "(index=False)"
            elif parsed_struct.get(invalid_field).get('required'):
                field = parsed_struct.get(invalid_field).get("field_type") + "(required=True)"
            doc += f'\n{model_name}._doc_type.mapping.properties._params["properties"]["{invalid_field}"] = {field}\n'
        return doc

    def prepare_innerdoc_model(self, parsed_struct, key, model_name):
        invalid_fields = []
        valid_fields = []

        if not parsed_struct['fields']:
            logging.error(f"Missing child properties for object type property, Property: {key}")
        innerdoc = """\n\nclass {}(InnerDoc):\n""".format(model_name)
        # add Meta class for dynamic=true/false
        if parsed_struct.get('dynamic') != 'strict':
            innerdoc += f"    class Meta:\n        dynamic = MetaField('{str(parsed_struct.get('dynamic')).lower()}')\n\n"

        parsed_struct = parsed_struct['fields']
        self.inner_docs.update({model_name: parsed_struct})
        for data in parsed_struct:
            if data == "class" or data.startswith("$"):
                logging.info(f"Skipping field {data}, invalid")
                invalid_fields.append(data)
                continue
            if parsed_struct.get(data).get("field_type"):
                field = self.prepare_field_text(parsed_struct, data)
            else:
                # Prepare Inner document model, If field is Object type and It has properties.
                if parsed_struct.get(data):
                    name = data.replace('_', '').capitalize()
                    # check InnerDoc model already created or not
                    check_exist = self.check_model_exist(name, parsed_struct.get(data)['fields'])
                    if not check_exist or check_exist == -1 or parsed_struct.get(data)['dynamic'] != 'strict':
                        # If model already created and it's properties are different then create new model with different name
                        if check_exist == -1 or parsed_struct.get(data)['dynamic'] != 'strict':
                            name += '_' + key
                        doc = self.prepare_innerdoc_model(parsed_struct.get(data), data, name)
                        self.inner_doc_text = self.inner_doc_text + doc
                    if parsed_struct.get(data)['fields']:
                        field = data + " = Object(" + name + ")"
                        if not parsed_struct.get(data).get('index'):
                            field = data + " = Object(" + name + ", enabled=False)"
                    else:
                        field = data + " = Object(enabled=False)"
            innerdoc += "    " + field + "\n"
            valid_fields.append(data)

        # if parsed_struct contain any invalid fields then need to append manually
        if not valid_fields:
            innerdoc += "    pass\n"
            if invalid_fields:
                # if innerdoc contain only invalid fields then in class then need to add Pass and create properties param
                innerdoc += model_name + '._doc_type.mapping.properties._params["properties"] = {}\n'

        innerdoc += self.prepare_invalid_fields(invalid_fields, parsed_struct, model_name)
        return innerdoc

    def write_models(self, models):
        if self.output_file:
            if isinstance(self.output_file,str):
                outf =  open(self.output_file,"w")
            else:
                # assuming file handler
                outf = self.output_file
        else:
            outf = sys.stdout
        try:
            timestamp = """\n# Timestamp :: {} // Timestamp in UTC\n""".format(datetime.datetime.utcnow())
            outf.write(models["import_statements"] + self.inner_doc_text + models["innerdoc"] + models["main_class"] +
                    models['invalid_fields'] + timestamp)
        finally:
            # if was a filename, close the file, delegate to caller
            if isinstance(self.output_file,str):
                outf.close()

    def generate(self):
        schemas = self.fetch_schemas()
        parsed = self.parse_schemas(schemas)
        models = self.generate_code(parsed)
        self.write_models(models)
