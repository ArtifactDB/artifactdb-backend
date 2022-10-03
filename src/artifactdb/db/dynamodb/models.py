# pylint: disable=abstract-method  # get_model() to be overriden in client
# pylint: disable=unused-import  # make common pynamodb attributes available to client imports
from datetime import datetime

from pynamodb.models import Model
from pynamodb.attributes import UnicodeAttribute, BooleanAttribute, NumberAttribute, MapAttribute, \
                                VersionAttribute, ListAttribute, TTLAttribute


class BaseModel(Model):
    """
    Base class for documents/records in DynamoDB
    """

    @classmethod
    def get_model(cls):
        """
        Return an instance of ModelBase with name/version set
        """
        raise NotImplementedError("implement me in sub-class")

    def __init__(self, *args, **kwargs):
        super().__init__(*args,**kwargs)
        self.model = self.__class__.get_model()

    # https://github.com/pynamodb/PynamoDB/issues/152#issuecomment-548249239
    def to_dict(self):
        ret_dict = {}
        for name, attr in self.attribute_values.items():
            ret_dict[name] = self._attr2obj(attr)

        return ret_dict

    def _attr2obj(self, attr):
        # compare with list class. It is not ListAttribute.
        if isinstance(attr, list):
            _list = []
            for _l in attr:
                _list.append(self._attr2obj(_l))
            return _list
        elif isinstance(attr, MapAttribute):
            _dict = {}
            for k,v in attr.attribute_values.items():
                _dict[k] = self._attr2obj(v)
            return _dict
        elif isinstance(attr, datetime):
            return attr.isoformat()
        else:
            return attr


class AuthorizableBaseModel(BaseModel):
    """
    Subclass for documents/records in DynamoDB (like BaseModel) but
    AuthorizableBaseModel is used when queries or scans have to
    be authorized
    """

    class Meta:
        host = None
        auth_fields = None


class ModelBase(MapAttribute):
    """
    Base class used to describe
    the mode used in the documents/records
    (model metadata)
    """
    name = UnicodeAttribute(null=False)
    version = UnicodeAttribute(null=False)


