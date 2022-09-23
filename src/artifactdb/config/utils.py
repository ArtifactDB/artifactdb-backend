import os
import glob
import json
import re
import tempfile
import logging

from urllib.parse import urlparse
from aumbry import YamlConfig
from aumbry.formats.yml import YamlHandler
import yaml
import aumbry

from artifactdb.utils import jsonpatch

# Fields that considered to be secret/password
URL_FIELDS_EXPRESSION = "uri|url|^result_backend$"
SECRET_FIELDS_EXPRESSION = "secret|token|key|password|^k$"


class PrintableYamlConfig(YamlConfig):
    """
    Adds to_dict() method to dump config while
    redacting sensitive information.
    """

    def to_dict(self,redact=True):
        return prepare_to_dict(self.__dict__,redact=redact)

    def __str__(self):
        return str(self.to_dict())


class ApiConfigBaseHandler(YamlHandler):
    post_hooks = []

    def run_post_hooks(self, cfg):
        for hook in self.post_hooks:
            cfg = hook(cfg)
        return cfg

    def deserialize(self, raw_config, config_cls):
        cfg = super().deserialize(raw_config, config_cls)
        cfg = self.run_post_hooks(cfg)
        return cfg


def prepare_to_dict(cfg_value, redact=True):
    """
        prepare dictionary for all config parameters
    """
    conf = {}
    for key, value in cfg_value.items():
        # "__..." kept as-is, but "_..." replaced (eg. for localstack)
        if key.count("_",0,2) == 1:
            key = key.replace('_','',1)
        if isinstance(value,dict):
            conf[key] = prepare_to_dict(value,redact=redact)
        elif isinstance(value,(bool, int, str)) or value is None:
            conf[key] = prepare_secret_values(key,value,redact=redact)
        elif isinstance(value,list):
            conf[key] = extract_list_config(key,value,redact=redact)
        else:
            conf[key] = prepare_to_dict(value.__dict__,redact=redact)
    return conf


def prepare_secret_values(key, value, redact=True):
    """
        Replace secret credential with ****
        Remove secret credential from URL
    """
    if re.search(URL_FIELDS_EXPRESSION, key):
        return redact_uri(value) if redact else value
    elif re.search(SECRET_FIELDS_EXPRESSION, key):
        if isinstance(value,str):
            return value[:1] + '******' if redact else value  #redact and value[:1] + "******" or value
        return value
    else:
        return value


def extract_list_config(key, value, redact=True):
    """Extract list type config parameter"""
    conf = []
    for each in value:
        if isinstance(each, dict):
            conf.append(prepare_to_dict(each,redact=redact))
        elif isinstance(each,(bool, int, str)):
            conf.append(prepare_secret_values(key, each, redact=redact))
        elif isinstance(each,PrintableYamlConfig):
            conf.append(each.to_dict(redact=True))
        else:
            conf.append(each)
    return conf


def get_config_file(env=None):
    env = env or os.environ.get("ARTIFACTDB_ENV","")
    files = []
    for base in ("config","patch"):
        pat = "./etc/{}{}*.yml".format(base,env and "-"+env or "")
        files.extend(glob.glob(pat))

    return files


def merge_config_files(config_files):
    """
    Merge all config files (in alnum order, assuming they're distinct
    from each other) into one single temporary file and returns it.
    `config_files` can also contain JSON diff files, starting with "path-*",
    which are applied once the plain "config-*" files are merged.
    """
    final = {}
    # there could be a mix of plain config files and patches
    cfg_files = [_ for _ in config_files if os.path.basename(_).startswith("config")]
    patch_files = [_ for _ in config_files if os.path.basename(_).startswith("patch")]
    for cfg_file in sorted(cfg_files):
        cfg = yaml.load(open(cfg_file),Loader=yaml.loader.Loader)
        final.update(cfg)
    for patch_file in sorted(patch_files):
        patches = yaml.load(open(patch_file),Loader=yaml.loader.Loader)
        if not patches:
            logging.warning(f"Patch config file {patch_file} exists but is empty, skipping it")
            continue
        final = jsonpatch.apply_patch(final,patches)
    _,filename = tempfile.mkstemp()
    with open(filename,"w") as fout:
        yaml.dump(final,fout)

    return filename


def preproc_env(cfg_data):
    """
    Preprocessor function injecting envionment variables
    when cfg_data (bytes) contains values like %(<env_name>)s
    """
    return cfg_data.decode() % os.environ


def prepare_config(config_class, config_file=None):
    configuration = aumbry.load(
        aumbry.FILE,
        config_class,
        {
            'CONFIG_FILE_PATH': config_file,
        },
        preprocessor=preproc_env,
    )
    configuration.config_file = config_file
    return configuration


def redact_uri(uri):
    puri = urlparse(uri)
    fmt = ""
    args = []
    if puri.username:
        # user + pass
        fmt = "{}:********@"
        args.append(puri.username)
    # hostname
    fmt += "{}"
    args.append(puri.hostname)
    if puri.port:
        fmt += ":{}"
        args.append(puri.port)
    newuri = puri._replace(netloc=fmt.format(*args))

    return newuri.geturl()


# Custom YAML loader/constructor to include yaml files
def construct_include(loader, node):
    """Include file referenced at node."""

    filename = os.path.abspath(os.path.join(os.path.curdir, loader.construct_scalar(node)))
    extension = os.path.splitext(filename)[1].lstrip('.')

    with open(filename, 'r') as fin:
        if extension in ('yaml', 'yml'):
            return yaml.load(fin, yaml.Loader)
        elif extension in ('json', ):
            return json.load(fin)
        else:
            return ''.join(fin.readlines())

yaml.add_constructor('!include', construct_include)


def init_model(klass, cfg):
    inst = klass()
    for name, attr in klass.__mapping__.items():
        try:
            value = cfg[name]
            # recursively init_model as needed
            if issubclass(attr.type,YamlConfig):
                value = init_model(attr.type,value)
            # None is still an allowed value whatever the type
            assert value is None or isinstance(value,attr.type), f"{value} should be typed as {attr.type}"
            setattr(inst,name,value)
        except KeyError:
            if attr.required:
                raise

    return inst


_CONFIG = None  # singleton, loaded configuration
def get_config(config_class, config_file=None, env=None):
    global _CONFIG
    if not _CONFIG is None:
        return _CONFIG

    config_files = [config_file] if config_file else get_config_file(env)
    print("Using config files: {}".format(config_files))
    final_config_file = merge_config_files(config_files)
    try:
        _CONFIG=prepare_config(config_class=config_class, config_file=final_config_file)
        return _CONFIG
    finally:
        # not needed anymore, limit the exposure secrets
        os.unlink(final_config_file)

