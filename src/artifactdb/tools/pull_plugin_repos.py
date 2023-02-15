from config import get_config # pylint: disable=no-name-in-module # get_config is taken from the instance of ArtifactDB
from artifactdb.backend.git import GitManager


def pull_plugin_repos():
    cfg = get_config()
    git_mgr = GitManager()
    git_mgr.get_repos(cfg.celery.repo, pull=True)

if __name__ == "__main__":
    pull_plugin_repos()
