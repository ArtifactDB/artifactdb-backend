from aumbry import Attr
from .utils import PrintableYamlConfig
from .storages import S3Config


class LocalstackConfig(PrintableYamlConfig):
    __mapping__ = {
        'enabled': Attr('enabled', bool),
        's3': Attr('s3', S3Config)
    }

    enabled = False


def extract_localstack_config_values(cfg):
    """
    extract localstack config values and replace these values with it's main config values.
    store the main values in another variable.
    With multiple storages enabled, it is assumed the first bucket is the one used for
    localstack
    """
    if hasattr(cfg,'localstack') and cfg.localstack.enabled:
        config = cfg.localstack.__dict__
        for key in config:
            if key != "enabled":
                setattr(cfg, f'source_{key}', getattr(cfg, key))
                setattr(cfg, key, config[key])
    return cfg



