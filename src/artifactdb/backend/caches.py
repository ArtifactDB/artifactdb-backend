import redis
import cacheout

from artifactdb.utils.misc import get_class_from_classpath


class CacheError(Exception): pass


def get_cache(cfg):
    # normalize to dict, `cfg` could be an aumbry instance or a dict
    if not isinstance(cfg, dict):
        cfg = cfg.to_dict()

    if not "backend" in cfg and ('type' in cfg or 'params' in cfg):
        raise CacheError("Cache configuration error, 'type' and/or 'params' must be under key 'backend'")

    cache_cfg = {
        "cache_ttl": cfg["cache_ttl"]
    }

    if "backend" in cfg:
        cache_cfg.update(cfg["backend"])
        cache_class = get_class_from_classpath(cfg["backend"]["type"])
        return cache_class(cache_cfg)
    else:
        return CacheoutCacheClient(cache_cfg)


class CacheClientBase:

    def __init__(self, cfg):
        self.cache_ttl = cfg["cache_ttl"]
        self.client = None

    def set(self,cache_key,value, ttl):
        raise NotImplementedError("Implement me in sub-class")

    def get(self,cache_key):
        return self.client.get(cache_key)

    def keys(self):
        return self.client.keys()

    def expired(self,cache_key):
        raise NotImplementedError("Implement me in sub-class")

    def delete(self, cache_key):
        self.client.delete(cache_key)

    def clear(self, keys=None):
        keys = keys or self.keys()
        for cache_key in keys:
            self.delete(cache_key)


class CacheoutCacheClient(CacheClientBase):

    def __init__(self, cfg):
        super().__init__(cfg)
        self.client = cacheout.Cache(ttl=self.cache_ttl, default=None)

    def expired(self, cache_key):
        return self.client.expired(cache_key)

    def set(self,cache_key, value, ttl):
        self.client.set(cache_key, value, ttl=ttl)


class RedisCacheClient(CacheClientBase):
    def __init__(self, cfg):
        super().__init__(cfg)
        self.client = redis.Redis(**cfg["params"])

    def expired(self,cache_key):
        # return 0 if key not exist else return 1, So, 0 consider as expired
        return self.client.exists(cache_key) == 0

    def set(self, cache_key, value, ttl):
        self.client.set(cache_key, value, ex=ttl)
