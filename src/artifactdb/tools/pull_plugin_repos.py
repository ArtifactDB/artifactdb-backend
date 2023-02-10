from config import get_config # pylint: disable=no-name-in-module # get_config is taken from the instance of ArtifactDB
from artifactdb.backend.git import GitManager


def pull_plugin_repos():
    cfg = get_config()
    repos_cfg = cfg.celery.get('repo', [])
    git_mgr = GitManager()
    repos_cfg = cfg.celery.get('repo', [])
    git_mgr.get_repos(repos_cfg, pull=True)

if __name__ == "__main__":
    pull_plugin_repos()
