import logging
import os

from git import Repo, InvalidGitRepositoryError
from git.exc import GitCommandError
from git.remote import FetchInfo


class GitManagerException(Exception):
    pass


# TODO: use @staticmethod for methods
class GitManager:

    def pull_repos(self, repos_cfg):
        fetch_tab = []
        for r_cfg in repos_cfg:
            repo_dir = self._get_repo_path(r_cfg)
            fetch_info = self._open_repo(repo_dir)['fetch']
            fetch_tab.append(fetch_info)

        return fetch_tab

    def _get_repo_path(self, repo_cfg):
        plugins_path = os.environ.get("PLUGINS_PATH")
        repo_name = repo_cfg['name']

        return f"{plugins_path}/{repo_name}"

    def _open_repo(self, repo_dir, pull = True):
        fetch = None
        try:
            repo = Repo(repo_dir)
            try:
                if pull:
                    fetch = repo.remotes.origin.pull()[0]
            except GitCommandError as exc:
                logging.exception(f"Repository not pulled because of exception: {exc}")
        except InvalidGitRepositoryError:
            logging.warning(f"Directory: '{repo_dir}' is not a correct git repository.")
            repo = None

        return {
            "repo": repo,
            "fetch": fetch
        }

    def _clone_repo(self, url, repo_dir, branch = None):
        if branch:
            repo = Repo.clone_from(url, repo_dir, branch=branch)
        else:
            repo = Repo.clone_from(url, repo_dir)

        return repo

    def is_any_repo_updated(self, fetch_tab):
        for fetch_info in fetch_tab:
            if self._is_repo_already_updated(fetch_info):
                return True
        return False

    def _is_repo_already_updated(self, fetch_info):
        if not fetch_info:
            return False
        flag = fetch_info.flags
        if flag == FetchInfo.HEAD_UPTODATE:
            return False
        elif flag == FetchInfo.FAST_FORWARD:
            return True
        else:
            raise GitManagerException(f"FetchInfo flag for repo pull: {flag}. Check: https://gitpython.readthedocs.io/en/stable/reference.html")

    def get_repos(self, repos_cfg, pull=True):
        for r_cfg in repos_cfg:
            self.get_plugin_repo(r_cfg, pull)

    def get_plugin_repo(self, repo_cfg, pull):
        repo_dir = self._get_repo_path(repo_cfg)
        if os.path.isdir(repo_dir):
            repo = self._open_repo(repo_dir, pull)['repo']
            if not repo:
                os.rmdir(repo_dir)
                logging.info(f"Directory: '{repo_dir}' has been removed.")
                repo = self._clone_repo(repo_cfg['url'], repo_dir, repo_cfg.get('branch'))
        else:
            repo = self._clone_repo(repo_cfg['url'], repo_dir, repo_cfg.get('branch'))

        return repo_dir

