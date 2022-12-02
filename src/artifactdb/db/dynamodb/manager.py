# pylint: disable=invalid-name  # dynamodb/boto3 use CamelCase args
import logging
import importlib
from time import sleep
from datetime import datetime
from decimal import Decimal
import copy


import dateparser
import boto3
from boto3.dynamodb.conditions import Attr, ConditionBase as boto3_comparison
from pynamodb.expressions.condition import Comparison as pynamodb_comparison

from artifactdb.rest.auth import RootUser
from artifactdb.utils.misc import get_class_from_classpath, random_id
from artifactdb.utils.context import auth_user_context, skip_auth_context
from .models import BaseModel, AuthorizableBaseModel


class ModelError(Exception): pass
class ObjectNotFound(Exception): pass
class ModelNotFound(Exception): pass
class UnableToAuthorize(Exception): pass


class DynamoDBManagerBase:

    def __init__(self, conf_dynamodb):
        self.cfg_ddb = conf_dynamodb
        self.client = boto3.client("dynamodb",region_name=self.cfg_ddb.region,
                                   endpoint_url=self.cfg_ddb.endpoint,
                                   aws_access_key_id=self.cfg_ddb.credentials.access_key,
                                   aws_secret_access_key=self.cfg_ddb.credentials.secret_key)
        self.resource = boto3.resource("dynamodb",region_name=self.cfg_ddb.region,
                                       endpoint_url=self.cfg_ddb.endpoint,
                                       aws_access_key_id=self.cfg_ddb.credentials.access_key,
                                       aws_secret_access_key=self.cfg_ddb.credentials.secret_key)
        self.register_models()
        self.init()
        # purge_ttl is a delta in seconds, to which we add now() when needed (expiration)
        purge_dt = dateparser.parse(str(self.cfg_ddb.purge_ttl))
        now = datetime.now()
        assert purge_dt > now, "Can't have purge_ttl in the past"
        self.purge_ttl = (purge_dt - now).total_seconds()
        logging.debug("DynamoDB endpoint: {}".format(self.client._endpoint))

    def generate_table_name(self, table):
        table_name = "{}-{}".format(self.cfg_ddb.db_name,table)
        if self.cfg_ddb.table_suffix:
            table_name += "-{}".format(self.cfg_ddb.table_suffix)

        return table_name

    def link_model(self, klass, table):
        # inject prefix in table_name, per environment / "database"
        fqdn_table_name = self.generate_table_name(table)
        setattr(klass.Meta,"table_name",fqdn_table_name)
        # set credentials and region (not specific to model kwargs
        klass.Meta.aws_access_key_id = self.cfg_ddb.credentials.access_key
        klass.Meta.aws_secret_access_key = self.cfg_ddb.credentials.secret_key
        klass.Meta.region = self.cfg_ddb.region
        klass.Meta.billing_mode = self.cfg_ddb.billing_mode
        if self.cfg_ddb.endpoint:
            klass.Meta.host = self.cfg_ddb.endpoint
        if issubclass(klass, AuthorizableBaseModel):
            if klass.Meta.auth_fields is None:
                raise ModelError("Authorizable model {} without authorizable fields specified for table: {}".format(klass, table))
            if not isinstance(klass.Meta.auth_fields, dict):
                raise ModelError("Wrong type of model {} Meta.auth_fields field for table: {}. Meta.auth_fields is {}, should be dict".format(klass, table, type(klass.Meta.auth_fields)))
        return klass

    def register_model(self, model_class, table):
        init_klass = self.link_model(model_class,table)
        model = init_klass.get_model()
        model_key = (model.name,model.version)
        if model_key in self.models[table]["models"]:
            prev = self.models[table]["models"][model_key]
            raise ModelError("Model already registered for {}: {}".format(model_key,prev))
        # per model name and version
        self.models[table]["models"][model_key] = init_klass

    def register_models(self):
        self.models = {}
        for table, declaration in self.cfg_ddb.models.items():
            base = get_class_from_classpath(declaration["base"])
            self.link_model(base,table)
            self.models.setdefault(table,{"base": base, "models": {}})
            for module_name in declaration["modules"]:
                mod = importlib.import_module(module_name)
                for something in dir(mod):
                    klass = getattr(mod,something)
                    try:
                        if issubclass(klass,base) and not klass is base:
                            logging.info("For table '{}', Found model {}".format(table,klass))
                            self.register_model(klass,table)
                    except TypeError:
                        # probably not even a class
                        continue

        return self.models

    def select_model_for_table(self, table):
        # All models within one table shares the same table, we just pick the one
        # that can be used (instanciable, not the "base" one, which is abstract)
        try:
            model = list(self.models[table]["models"].values())[0]
            return model
        except KeyError:
            raise ModelNotFound("Can't find model for table '{}'".format(table))

    def select_model_for_item(self, item, table):
        try:
            # raw DDB structure using client
            name = item["model"]["M"]["name"]["S"]
            version = item["model"]["M"]["version"]["S"]
        except KeyError:
            try:
                # raw DDB structure using Table resource
                name = item["model"]["name"]
                version = item["model"]["version"]
            except KeyError as e:
                raise ModelError("Can't extract model name/version from item: {} (item={})".format(e,repr(item)))
        try:
            return self.models[table]["models"][(name,version)]
        except KeyError:
            raise ModelNotFound("Can't find model for '{}/{}'".format(name,version))

    def select_latest_model(self, model_name, table):
        """
        Return latest model (according to version number) matching
        "model_name" in "table"
        """
        try:
            models = self.models[table].get("models",[])
            # keys look like ("name","version")
            matchings = [(k,v) for k,v in models.items() if k[0] == model_name]
            latest = sorted(matchings,key=lambda e: e[0][1],reverse=True)[0]
            return latest[1]  # actual class
        except KeyError:
            raise ModelError("Can't find models for table '{}'".format(table))
        except IndexError:
            raise ModelError("Can't find model named '{}'".format(model_name))

    def init(self, purge=False, table_name=None, max_retry=10):
        for table,dmodels in self.models.items():
            if table_name and table_name != table:
                continue
            # we use the base model, which should contain all the critical schema def (2nd index, etc...)
            base = dmodels["base"]
            if purge and base.exists():
                base.delete_table()
                retry = max_retry
                deleted = False
                while retry:
                    if base.Meta.table_name in self.client.list_tables().get("TableNames",[]):
                        logging.info("Waiting for table '{}' deletion".format(base.Meta.table_name))
                        retry -= 1
                        sleep(1.)
                    else:
                        deleted = True
                        break
                if not deleted:
                    raise ModelError("Timeout while waiting for table deletion")
            if not base.exists():
                logging.info("Creating DynamoDB table '{}', from base model {}".format(table,base))
                base.create_table(wait=True)

    def generate_id(self, obj):
        """Generate random ID for given object"""
        return random_id(obj)

    def truncate(self, table):
        model = self.select_model_for_table(table)
        with model.batch_write() as batch:
            scan = model.scan()
            for doc in scan:
                batch.delete(doc)

    def scan(self, table, filter_condition=None):
        """uses pynamodb model to scan DynamoDB table using pynamodb model

        Args:
            table (str): table name used to select model, e.g. action
            filter_condition (pynamodb.expressions.condition.Comparison, optional): additional data filtering (applied AFTER table was queried). Defaults to None.

        Returns:
            generator: elements returned by scan with pynamodb model
        """
        model = self.select_model_for_table(table)
        if issubclass(model, AuthorizableBaseModel):
            filter_condition = self.authorize_ddb_request(model, filter_condition, query_type="pynamodb")
        return model.scan(filter_condition=filter_condition)

    def scan_raw(self, table, FilterExpression=None, Limit=None, ExclusiveStartKey=None):
        """uses boto3.resource to scan DynamoDB table using boto3 resource instead of pynamodb model (allows to bypass checks made by pynamodb model)

        Args:
            table (str): table name used to select model, e.g. action
            FilterExpression (boto3.dynamodb.conditions.Attr, optional): additional data filtering (applied AFTER table was queried). Defaults to None.

        Returns:
            dict: dictionary returned by scan made with boto3.resource scan for DynamoDB table
        """
        table_name = self.generate_table_name(table)
        model = self.select_model_for_table(table)
        if issubclass(model, AuthorizableBaseModel):
            FilterExpression = self.authorize_ddb_request(model, FilterExpression, query_type="boto3")
        # boto3 dynamodb Table resource will NOT accept None as argument value
        # so we have to take care of FilterExpression having value None
        kwargs = {}
        if FilterExpression:
            kwargs["FilterExpression"] = FilterExpression
        if Limit:
            kwargs["Limit"] = Limit
        if ExclusiveStartKey:
            kwargs["ExclusiveStartKey"] = ExclusiveStartKey
        ddb_table = self.resource.Table(table_name)
        return ddb_table.scan(**kwargs)

    def query(self, table, hash_key, index_name=None, range_key_condition=None, filter_condition=None):
        """uses pynamodb model to query data, argument names are same as those used by pynamodb model query

        Args:
            table (str): table name used to select model, e.g. action
            hash_key (str): value to query, e.g. element id
            index_name (str, optional): name of index to query, if None then default table id is queried. Defaults to None.
            range_key_condition (pynamodb.expressions.condition.Comparison, optional): if range key is present, then it can be used when querying data. Defaults to None.
            filter_condition (pynamodb.expressions.condition.Comparison, optional): additional data filtering (applied AFTER table was queried). Defaults to None.

        Returns:
            generator: elements returned by query with pynamodb model
        """
        model = self.select_model_for_table(table)
        if issubclass(model, AuthorizableBaseModel):
            filter_condition = self.authorize_ddb_request(model, filter_condition, query_type="pynamodb")
        return model.query(hash_key=hash_key, index_name=index_name, range_key_condition=range_key_condition, filter_condition=filter_condition, page_size=3)

    def query_raw(self, table, KeyConditionExpression, IndexName=None, FilterExpression=None, Limit=None, ExclusiveStartKey=None):
        """uses boto3.resource to query dynamodb tables, allows to bypass checks made by pynamodb models
        (useful when data for more than one model is stored in table) argument names are same
        like for boto3 dynamodb.Table.query() which is called by function

        Args:
            table (str): table name used to select model, e.g. action
            KeyConditionExpression (boto3.dynamodb.conditions.Key): value to query, e.g. element id when index_name="id", or user unixid e.g. "dobekd" if index_name="owner"
            IndexName (str, optional): describes which field to query with value passed in key argument. Defaults to None. If None then main table key will be queried
            FilterExpression (boto3.dynamodb.conditions.Attr, optional): additional data filtering (applied AFTER table was queried). Defaults to None.
            Limit (int, optional): maximum number of items to evaluate. If limit number or 1MB was reached then DynamoDB stops the operation and includes LastEvaluatedKey in response
                                   that can be used to create next subquery. Defaults to None.
            ExclusiveStartKey (dict, optional): id of last element in previous query (LastEvaluatedKey field), can be passed here to specify key value of first element for query.

        Returns:
            dict: dictionary returned by query made with boto3.resource query for DynamoDB table
        """
        table_name = self.generate_table_name(table)
        # do not forget about authorizable queries
        model = self.select_model_for_table(table)
        if issubclass(model, AuthorizableBaseModel):
            FilterExpression = self.authorize_ddb_request(model, FilterExpression, query_type="boto3")
        ddb_table = self.resource.Table(table_name)
        # boto3 dynamodb Table resource will NOT accept None as argument values
        kwargs = {"KeyConditionExpression": KeyConditionExpression}
        if IndexName:
            kwargs["IndexName"] = IndexName
        if FilterExpression:
            kwargs["FilterExpression"] = FilterExpression
        if Limit:
            kwargs["Limit"] = Limit
        if ExclusiveStartKey:
            kwargs["ExclusiveStartKey"] = ExclusiveStartKey
        return ddb_table.query(**kwargs)

    def save_raw(self, obj, force=True):
        assert isinstance(obj,BaseModel), "Unknown object type {}".format(type(obj))
        if force:
            obj.save()
        else:
            obj.save(obj.__class__.id.does_not_exist())
        return obj.id

    def delete(self, obj, table, id_field="id"):
        if isinstance(obj,BaseModel):
            obj_id = getattr(obj, id_field)
        else:
            obj_id = obj
        # we can't know if object exists or not, it's silent
        self.delete_raw(obj_id,table, id_field=id_field)

    def delete_raw(self, object_id, table, id_field = "id"):
        # TODO: refactor with get_raw() ?
        table_name = self.generate_table_name(table)
        try:
            model = self.select_model_for_table(table)
        except ModelNotFound:
            raise ObjectNotFound(object_id)
        params = {
            "TableName": table_name,
            "Key": {id_field: {"S": str(object_id)}}
        }
        try:
            if issubclass(model, AuthorizableBaseModel):
                params = self.authorize_ddb_request(model, params)
            raw_data = self.client.delete_item(**params)
            return raw_data
        except self.client.exceptions.ResourceNotFoundException as e:
            return e.response
        except self.client.exceptions.ConditionalCheckFailedException as e:
            return e.response

    def get(self, object_id, table, id_field="id"):
        """
        Return a PynamoDB model instance, as define in identified by object_id.
        The item contains a "model" key describing which PynamoDB model should be
        used to deserialize the content and build a proper python object.
        """
        # first, fetch raw item
        raw_data = self.get_raw(object_id,table,id_field)
        item = raw_data and raw_data.get("Item")
        if not item:
            raise ObjectNotFound(object_id)
        model_class = self.select_model_for_item(item,table)
        obj = model_class()
        obj._deserialize(item)

        return obj

    def get_raw(self, object_id, table, id_field="id"):
        table_name = self.generate_table_name(table)
        try:
            model = self.select_model_for_table(table)
        except ModelNotFound:
            raise ObjectNotFound(object_id)
        params = {
            "TableName": table_name,
            "KeyConditionExpression": "{} = :val".format(id_field),
            "ExpressionAttributeValues": {":val": {"S": str(object_id)}}
        }
        if id_field != "id":
            params["IndexName"] = "{}_index".format(id_field)
        try:
            if issubclass(model, AuthorizableBaseModel):
                auth_params = self.authorize_ddb_request(model, params)
                raw_data = self.client.query(**auth_params)
            else:
                if id_field == "id":
                    # fetch by primary key (cost efficiency)
                    raw_data = self.client.get_item(TableName=table_name,Key={ id_field :{"S":str(object_id)}})
                    return raw_data
                else:
                    raw_data = self.client.query(**params)
            if raw_data["Items"]:
                assert len(raw_data["Items"]) == 1, "More than 1 item found: {}".format(raw_data)
                # reformat as it was a fetch (only one Item)
                item = raw_data["Items"][0]
                raw_data.pop("Items")
                raw_data["Item"] = item
            else:
                return None

            return raw_data

        except self.client.exceptions.ResourceNotFoundException as e:
            return e.response

    def authorize_ddb_request(self, model, params=None, query_type=None):
        """
        Adds query (or filter) elements to given argument params
        e.g. adds authorization during querying time.
        Tables for which queries have to be changesd together with fields used to
        adjust queries are stored in DynamoDBConfig field (dict) tables_to_auth.
        Currently only one scalar field can be filtered with one unique value of
        user unixID taken from auth_context. The field to check must be a string.

        * model - allows to check table and is necessary to prepare query for model.scan() filter
        * params - can be of two types:
            - dictionary - type acceptable by boto3 DynamoDB client queries (alternative to boto3 Condition)
            - pynamodb Comparison - type used by model.scan() calle with pynamodb Comparisons
            - boto3 Condition - type used by queries made with boto3 client and resource when data is not specified as dictionary
        * query_type - type of params, if not provided it can be obtained from params type (if present),
            if params argument is present - type of query will be obtained from params, possible values:
            - "boto3"
            - "pynamodb"
            - "dict"
        """

        def get_auth_value(auth_type, user_context):
            if auth_type == "unixID":
                if user_context.unixID:
                    return user_context.unixID
                else:
                    raise UnableToAuthorize("No user ID found in context")
            else:
                raise UnableToAuthorize("Unknown authorization type: {}".format(auth_type))

        def authorize_ddb_pynamodb_condition(auth_value, auth_field, filter_condition=None):
            # eg. auth_field = owner, auth_value = unixID
            if filter_condition is None:
                return getattr(model, auth_field)==auth_value
            else:
                return filter_condition & (getattr(model, auth_field)==auth_value)

        def authorize_ddb_boto3_condition(auth_value, auth_field, filter_condition=None):
            # eg. auth_field = owner, auth_value = unixID
            if filter_condition is None:
                return Attr(auth_field).eq(auth_value)
            else:
                return filter_condition & (Attr(auth_field).eq(auth_value))

        def authorize_ddb_query_or_delete(auth_value, auth_field, params_dict):
            # eg. auth_field = owner, auth_value = unixID
            expression_field = "ConditionExpression" if "Key" in params_dict else "FilterExpression"
            if not "ExpressionAttributeValues" in params_dict:
                params_dict["ExpressionAttributeValues"] = {}
            params_dict["ExpressionAttributeValues"][f":field_{auth_field}_filter"] = {"S" : auth_value}
            params_dict["ExpressionAttributeNames"] = {f"#field_{auth_field}" : f"{auth_field}"}
            if expression_field in params_dict:
                params_dict[expression_field] = f" or #field_{auth_field} = :field_{auth_field}_filter"
            else:
                params_dict[expression_field] = f"#field_{auth_field} = :field_{auth_field}_filter"
            return params_dict

        authorizer_func = {
            "boto3": {"func":authorize_ddb_boto3_condition, "kwargs":{"filter_condition":params}},
            "pynamodb": {"func":authorize_ddb_pynamodb_condition, "kwargs":{"filter_condition":params}},
            "dict": {"func":authorize_ddb_query_or_delete, "kwargs":{"params_dict":params}}
        }

        skip_auth = skip_auth_context.get()
        current_user = auth_user_context.get()

        auth_fields = model.Meta.auth_fields

        if skip_auth:
            logging.info("For user '{}', skipping auth, query is: {}".format(current_user,params))
            return params
        if not current_user:
            raise UnableToAuthorize("No user context found")

        if isinstance(current_user, RootUser):
            # skip terms query to filter data, we return everything
            return params

        # chek with what type of query we have to deal
        if not query_type in [None, "boto3", "pynamodb", "dict"]:
            raise UnableToAuthorize(f"Unknown query type: {query_type}, must be one of ('boto3', 'pynamodb', 'dict') or None")
        if params is None:
            if query_type is None:
                raise UnableToAuthorize("Unable to Authorize request: at least one of arguments (params, type) must be provided")
        elif isinstance(params, boto3_comparison):
            query_type = "boto3"
        elif isinstance(params, pynamodb_comparison):
            query_type = "pynamodb"
        elif isinstance(params, dict):
            query_type = "dict"
        elif query_type is None:
            raise UnableToAuthorize(f"Unknown query / filter object {params} of type {type(params)} - unable to authorize")


        try:
            for auth_field, auth_type in auth_fields.items():
                auth_value = get_auth_value(auth_type, current_user)
                auth_params = copy.deepcopy(authorizer_func[query_type]["kwargs"])
                auth_params.update({"auth_field":auth_field, "auth_value":auth_value})
                params = authorizer_func[query_type]["func"](**auth_params)
                return params
        except Exception as e:
            raise UnableToAuthorize(f"Unable to authorize DynamoDB query / filter request with following exception {e}")


    def replace_decimals(self, number):
        """
        helper to get rid of Decimals - type of numeric values returned from boto3 dynamodb.Table query
            number - object that possibly contains Decimals
        """
        if isinstance(number, Decimal):
            number = float(number)
        elif isinstance(number, dict):
            for k in number:
                number[k] = self.replace_decimals(number[k])
        elif isinstance(number, list):
            for i,num in enumerate(number):
                number[i] = self.replace_decimals(num)
        return number

    def describe_table(self, table):
        """Function returns table description from DynamoDB."""
        table_name = self.generate_table_name(table)
        return self.client.describe_table(TableName=table_name)['Table']
