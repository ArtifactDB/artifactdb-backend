import os

from .utils import prepare_config


def get_plugin_config(config_class, repo_cfg, config_file):
    """
    Configuration for plugins.
    Parameters:
    - config_class - descendang of YamlConfig
    - config_file - relative path to config file in plugin repository
    - repo_cfg - repo config from host ArtifactDB instance
    """
    folder = repo_cfg["name"]
    plugins_path = os.environ["PLUGINS_PATH"]

    config_file=f"{plugins_path}/{folder}/{config_file}"
    return prepare_config(config_class=config_class, config_file=config_file)
