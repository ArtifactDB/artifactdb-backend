import datetime
import uuid
import base64
import json

import redis
import dateparser

from . import DEFAULT_SCROLL

class CustomScrollError(Exception): pass
class CustomScrollExpired(Exception): pass
class NoSuchCustomScroll(Exception): pass


class Scroller:

    def __init__(self, scroll_cfg):
        self.client = redis.Redis(**scroll_cfg["backend"]["params"])
        self.default_expire = (datetime.datetime.now() - dateparser.parse(DEFAULT_SCROLL)).seconds

    def generate(self, func_name, data, ex=None):
        """
        Generate a scroll ID, composed by func_name to indicate
        which callable should handle subsequent scroll calls. Data
        is the value stored for the scroll ID, as a json string
        """
        _id = base64.b64encode(uuid.uuid4().hex.encode()).decode()
        # we add a prefix to mark the scroll as custom
        _id = "{}-{}-{}".format(base64.b64encode(b"custom").decode(),
                                base64.b64encode(func_name.encode()).decode(),
                                _id)
        self.set(_id,data,ex=ex)
        return _id

    def set(self, _id, data, ex=None):
        ex = ex or self.default_expire
        jdata = json.dumps(data)
        self.client.set(_id,jdata,ex=ex)

    def get(self, _id):
        jdata = self.client.get(_id)
        if not jdata:
            if self.client.ttl(_id) == -2:
                raise CustomScrollExpired(_id)
            raise NoSuchCustomScroll(_id)
        data = json.loads(jdata)

        return data

    def clear(self, _id):
        return self.client.delete(_id)

