import copy
import logging

from aumbry import Attr
from .utils import PrintableYamlConfig, init_model
from .credentials import AWSCredentials
from .switches import Switch


class S3Config(PrintableYamlConfig):
    __mapping__ = {
        'endpoint': Attr('endpoint', str),
        'bucket': Attr('bucket', str),
        'credentials': Attr('credentials', AWSCredentials),
        'presigned_url_expiration': Attr('presigned_url_expiration', str),
        'signature_version': Attr('signature_version', str),
        'region': Attr('region', str),
        'meta_redirect': Attr('meta_redirect', str),
        'delete_stale_projects_older_than': Attr('delete_stale_projects_older_than', str),
        'multipart_threshold': Attr('multipart_threshold', str),
        'expiration_rule': Attr('expiration_rule',bool), # bucket expiration rules
        'bucket_versioning': Attr('bucket_versioning',bool)
    }
    endpoint = ''
    credentials = AWSCredentials()
    presigned_url_expiration = 2*60*60  # 2 hours default
    signature_version = None
    region = None
    meta_redirect = "artifactdb-link"  # name of x-amz-meta field to tag redirection/symlinks
    # delete project from s3 if not completed and older than define time
    delete_stale_projects_older_than = "2 weeks ago"
    multipart_threshold = "100MB"
    expiration_rule = None
    # expiration rule is responsible for determining state of the default
    # expiration rule with id "expired", three possible values points to three
    # different behaviours:
    #       + when value is True, then new default expiration rule will be created,
    # if the old one was present then it will be overwritten by new one
    #       + when value is False, then existsing default expiration rule will
    # will be removed (if exists)
    #       + when value is None, or no value, then no changes will be applied to
    # existing expiration rules
    bucket_versioning = None
    # similar behavior to that for expiration_rule:
    #       + when value is True, then s3 bucket versioning will be enabled
    #       + when value is False, then s3 bucket versioning will be disabled
    #       + when value is None or no value was specified, then s3 bucket versioning won't be changed


# S3 inventory
class S3InventoryConfig(PrintableYamlConfig):
    __mapping__ = {
        'inventory_bucket': Attr('inventory_bucket', str),
        'folder': Attr('folder', str),
        'credentials': Attr('credentials', AWSCredentials),
        'use_to_clean_stale_projects': Attr('use_to_clean_stale_projects',bool),
    }

    use_to_clean_stale_projects = False  # search for ..deleteme files using inventories instead of querying s3
    inventory_bucket = None
    folder = None
    credentials = AWSCredentials()


class StorageClientConfig(PrintableYamlConfig):
    __mapping__ = {
        "alias": Attr("alias",str),
        "type": Attr("type",str),
        "s3": Attr('s3', S3Config),
    }

class StorageConfig(PrintableYamlConfig):
    __mapping__ = {
        "clients": Attr("clients",list),
        "switch": Attr("switch",Switch)
    }
    clients = []

    def to_dict(self, *args, **kwargs):
        oned = super().to_dict(*args,**kwargs)
        oned.pop("__clients__",None)  # was a copy of original, no need to expose
        return oned


def set_storage_models(cfg):
    clients = []
    for storecfg in cfg.storage.clients:
        clients.append(init_model(StorageClientConfig,storecfg))
    # replace with instantiated config model
    cfg.storage.__clients__ = copy.deepcopy(cfg.storage.clients)
    cfg.storage.clients = clients

    return cfg


def set_legacy_s3_config(cfg):
    """
    For backward compatibility, we assume the first storage
    is the default and primary/active one, so we restore the
    legacy config `s3` attribute back to this first storage.
    """
    assert len(cfg.storage.clients) > 0, "At least one storage is expected"
    assert cfg.storage.clients[0].type == "s3"
    logging.debug("Setting cfg.s3 legacy storage config as {}".format(cfg.storage.clients[0].to_dict()))
    cfg.s3 = cfg.storage.clients[0].s3

    return cfg


