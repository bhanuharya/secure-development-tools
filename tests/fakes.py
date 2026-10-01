import shutil
from pathlib import Path

from src.integrations.bitbucket_client import BitbucketClient


class FakeBitbucket(BitbucketClient):
    """Local, Bitbucket-shaped client used for tests. Clones a local worktree."""

    def __init__(self, source_workdir: Path, diff_text: str = "", head_sha: str = "aabbccddeeff00112233445566778899aabbccdd") -> None:
        self.source = Path(source_workdir)
        self.diff_text = diff_text
        self.head_sha = head_sha
        self.clone_dirs: list[Path] = []

    def list_repos(self, workspace, cursor=None, page_len=100):
        from src.integrations.bitbucket_client import Paginated

        return Paginated(values=[{"slug": "demo", "name": "demo", "language": "python"}], next_cursor=None)

    def get_repo(self, workspace, repo):
        return {"name": "demo", "slug": "demo", "mainbranch": {"name": "main"}}

    def list_branches(self, workspace, repo, cursor=None, page_len=100):
        from src.integrations.bitbucket_client import Paginated

        return Paginated(values=[{"name": "main", "target": {"hash": self.head_sha}}], next_cursor=None)

    def list_pull_requests(self, workspace, repo, state="OPEN"):
        return [{"id": 5, "state": "OPEN", "title": "demo"}]

    def get_pull_request_diff(self, workspace, repo, pr_id):
        return self.diff_text

    def pull_request_head_sha(self, workspace, repo, pr_id):
        return self.head_sha

    def clone_repo(self, workspace, repo, ref, dest, depth=1):
        dest = Path(dest)
        shutil.copytree(self.source, dest)
        self.clone_dirs.append(dest)

    def branch_head_sha(self, workspace, repo, branch):
        return self.head_sha