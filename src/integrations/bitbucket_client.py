from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, quote, urlparse

import httpx

from src.config import BITBUCKET_ACCESS_TOKEN, BITBUCKET_API_BASE, BITBUCKET_WORKSPACE

log = logging.getLogger(__name__)

BITBUCKET_CLONE_HOST = "bitbucket.org"

# Git needs process lookup, locale, TLS trust, and (in some environments) proxy
# settings. Do not pass the complete service environment: it contains unrelated
# control-plane and scanner credentials that Git and its helpers do not need.
_GIT_ENV_ALLOWLIST = (
    "PATH",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "https_proxy",
    "http_proxy",
    "no_proxy",
)


_GIT_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,254}")
_PR_ID_RE = re.compile(r"[1-9][0-9]{0,9}")
_COMPONENT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


def _validate_component(value: str, name: str) -> str:
    if not value or not _COMPONENT_RE.fullmatch(value):
        raise BitbucketError(f"invalid Bitbucket {name}")
    return value


def _validate_git_ref(ref: str) -> str:
    if re.fullmatch(r"[0-9a-fA-F]{40}", ref or ""):
        return ref
    if (
        not ref
        or ref.startswith("-")
        or not _GIT_REF_RE.fullmatch(ref)
        or ".." in ref
        or "@{" in ref
        or ref.endswith(("/", ".", ".lock"))
    ):
        raise BitbucketError("invalid Git ref")
    return ref


def _validate_pr_id(pr_id: str | int) -> str:
    value = str(pr_id)
    if not _PR_ID_RE.fullmatch(value):
        raise BitbucketError("invalid pull-request id")
    return value


class BitbucketError(Exception):
    """Raised for Bitbucket API failures."""


@dataclass
class Paginated:
    values: list[dict]
    next_cursor: str | None = None  # opaque cursor string (the Bitbucket `next` URL)


class BitbucketClient:
    def __init__(
        self,
        token: str = "",
        base_url: str = BITBUCKET_API_BASE,
        timeout: float = 30.0,
    ) -> None:
        self.token = token or BITBUCKET_ACCESS_TOKEN
        if not self.token:
            raise BitbucketError("No Bitbucket access token configured (BITBUCKET_ACCESS_TOKEN)")
        self.base_url = base_url.rstrip("/")
        self._client = httpx.Client(
            base_url=self.base_url,
            headers={"Authorization": f"Bearer {self.token}"},
            timeout=timeout,
        )

    def close(self) -> None:
        self._client.close()

    def _get(self, path: str, params: dict | None = None) -> dict:
        resp = self._client.get(path, params=params)
        if resp.status_code == 404:
            raise BitbucketError(f"Not found: {path}")
        if resp.status_code == 403:
            raise BitbucketError("Access token lacks required scope (repository:read / pullrequest:read)")
        if resp.status_code == 401:
            raise BitbucketError("Bitbucket access token rejected (401)")
        if resp.status_code >= 400:
            raise BitbucketError(f"Bitbucket API {resp.status_code} on {path}: {resp.text[:300]}")
        return resp.json()

    def _extract_cursor(self, payload: dict) -> str | None:
        nxt = payload.get("next")
        if not nxt:
            return None
        parsed = urlparse(nxt)
        base_path = urlparse(str(self._client.base_url)).path.rstrip("/")
        path = parsed.path
        if base_path and path.startswith(f"{base_path}/"):
            path = path[len(base_path):]
        return f"{path}?{parsed.query}" if parsed.query else path

    def _paginate(self, path: str, page_len: int = 100, cursor: str | None = None) -> Paginated:
        if cursor:
            # cursor is an opaque path+query string taken from a previous `next` URL.
            # Replay it (cursor token first, pagelen merged when absent) so
            # pagination survives Bitbucket's opaque cursor tokens.
            parsed = urlparse(cursor)
            query = dict(parse_qsl(parsed.query, keep_blank_values=True))
            params: list[tuple[str, str]] = []
            if "cursor" in query:
                params.append(("cursor", query.pop("cursor")))
            params.extend(query.items())
            if not any(k == "pagelen" for k, _ in params):
                params.append(("pagelen", str(page_len)))
            path = parsed.path or path
        else:
            params = [("pagelen", str(page_len))]
        payload = self._get(path, params=params)
        return Paginated(values=payload.get("values", []), next_cursor=self._extract_cursor(payload))

    # ------------------------------------------------------------------ repos
    def list_repos(self, workspace: str, cursor: str | None = None, page_len: int = 100) -> Paginated:
        workspace = _validate_component(workspace, "workspace")
        return self._paginate(f"/repositories/{workspace}", page_len=page_len, cursor=cursor)

    def get_repo(self, workspace: str, repo: str) -> dict:
        workspace = _validate_component(workspace, "workspace")
        repo = _validate_component(repo, "repository")
        return self._get(f"/repositories/{workspace}/{repo}")

    def get_default_branch(self, workspace: str, repo: str) -> str:
        data = self.get_repo(workspace, repo)
        return data.get("mainbranch", {}).get("name") or "main"

    def repo_clone_url(self, workspace: str, repo: str) -> str:
        """HTTPS clone URL without credentials.

        The access token is never embedded in the URL (it would leak via
        process argv and persist in .git/config). Authentication is supplied
        at clone time through a mode-0600 GIT_ASKPASS helper instead.
        """
        workspace = _validate_component(workspace, "workspace")
        repo = _validate_component(repo, "repository")
        host = BITBUCKET_CLONE_HOST
        return f"https://{host}/{workspace}/{repo}.git"

    # ---------------------------------------------------------------- branches
    def list_branches(self, workspace: str, repo: str, cursor: str | None = None, page_len: int = 100) -> Paginated:
        workspace = _validate_component(workspace, "workspace")
        repo = _validate_component(repo, "repository")
        return self._paginate(
            f"/repositories/{workspace}/{repo}/refs/branches", page_len=page_len, cursor=cursor
        )

    def branch_head_sha(self, workspace: str, repo: str, branch: str) -> str:
        workspace = _validate_component(workspace, "workspace")
        repo = _validate_component(repo, "repository")
        safe_branch = _validate_git_ref(branch)
        data = self._get(f"/repositories/{workspace}/{repo}/refs/branches/{quote(safe_branch, safe='')}")
        return data.get("target", {}).get("hash", "")

    # --------------------------------------------------------------------- PRs
    def list_pull_requests(self, workspace: str, repo: str, state: str = "OPEN") -> list[dict]:
        workspace = _validate_component(workspace, "workspace")
        repo = _validate_component(repo, "repository")
        page = self._paginate(f"/repositories/{workspace}/{repo}/pullrequests", page_len=100)
        results = list(page.values)
        while page.next_cursor:
            page = self._paginate(f"/repositories/{workspace}/{repo}/pullrequests", cursor=page.next_cursor)
            results.extend(page.values)
        wanted = state.upper()
        if wanted in ("OPEN", "MERGED", "DECLINED", "SUPERSEDED"):
            results = [pr for pr in results if (pr.get("state") or "").upper() == wanted]
        return results

    def get_pull_request(self, workspace: str, repo: str, pr_id: str | int) -> dict:
        workspace = _validate_component(workspace, "workspace")
        repo = _validate_component(repo, "repository")
        safe_pr = _validate_pr_id(pr_id)
        return self._get(f"/repositories/{workspace}/{repo}/pullrequests/{safe_pr}")

    def pull_request_head_sha(self, workspace: str, repo: str, pr_id: str | int) -> str:
        data = self.get_pull_request(workspace, repo, pr_id)
        return data.get("source", {}).get("commit", {}).get("hash", "")

    def get_pull_request_diff(self, workspace: str, repo: str, pr_id: str | int) -> str:
        workspace = _validate_component(workspace, "workspace")
        repo = _validate_component(repo, "repository")
        safe_pr = _validate_pr_id(pr_id)
        resp = self._client.get(
            f"/repositories/{workspace}/{repo}/pullrequests/{safe_pr}/diff",
            headers={"Accept": "text/plain"},
        )
        if resp.status_code >= 400:
            raise BitbucketError(f"Failed to fetch PR diff: {resp.status_code}")
        return resp.text

    # ------------------------------------------------------------------- clone
    def clone_repo(self, workspace: str, repo: str, ref: str, dest: str, depth: int = 1) -> None:
        """Clone a branch (or commit sha) into dest. ref may be a branch name or SHA.

        The token never appears in argv or .git/config: git authenticates via
        a temporary mode-0600 GIT_ASKPASS script that is removed afterwards,
        and the stored origin URL carries no credentials.
        """
        if shutil.which("git") is None:
            raise BitbucketError("git binary not available")
        if BITBUCKET_WORKSPACE and workspace != BITBUCKET_WORKSPACE:
            raise BitbucketError("requested workspace is outside the configured Bitbucket scope")
        if depth < 1:
            raise BitbucketError("clone depth must be positive")
        ref = _validate_git_ref(ref)
        url = self.repo_clone_url(workspace, repo)
        askpass = _write_askpass(self.token)
        try:
            cmd = [
                "git",
                "-c",
                "core.symlinks=false",
                "-c",
                "credential.helper=",
                "clone",
                "--quiet",
                "--no-tags",
                "--no-checkout",
                "--depth",
                str(depth),
            ]
            if re.fullmatch(r"[0-9a-fA-F]{40}", ref or ""):
                cmd += [url, dest]
                self._run(cmd, askpass=askpass)
                self._run(
                    ["git", "-c", "credential.helper=", "-C", dest, "fetch", "--quiet", "--depth", str(depth), "origin", ref],
                    askpass=askpass,
                )
                self._run(
                    ["git", "-c", "credential.helper=", "-C", dest, "checkout", "--quiet", "--detach", ref],
                    askpass=askpass,
                )
            else:
                cmd += ["--branch", ref, "--single-branch", url, dest]
                self._run(cmd, askpass=askpass)
                self._run(
                    ["git", "-c", "credential.helper=", "-C", dest, "checkout", "--quiet", "--detach"],
                    askpass=askpass,
                )
            _reject_worktree_symlinks(dest)
        finally:
            _remove_askpass(askpass)
            _scrub_git_config(dest, self.token)

    def _run(self, cmd: list[str], cwd: str | None = None, askpass: str | None = None) -> str:
        env = {name: os.environ[name] for name in _GIT_ENV_ALLOWLIST if name in os.environ}
        env.setdefault("PATH", os.defpath)
        env["GIT_TERMINAL_PROMPT"] = "0"
        if askpass:
            env["GIT_ASKPASS"] = askpass
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            env=env,
        )
        if proc.returncode != 0:
            raise BitbucketError(
                f"Command failed ({' '.join(self._redact_secret(part) for part in cmd[:3])}...): "
                f"{self._redact_secret(proc.stderr).strip()[:400]}"
            )
        return proc.stdout

    def _redact_secret(self, text: str) -> str:
        """Remove the access token and any credential-bearing URL form from
        diagnostics so a failed clone never persists or displays a credential."""
        out = text
        if self.token:
            out = out.replace(self.token, "[REDACTED]")
        out = re.sub(r"x-token-auth:[^@\s]+@", "[REDACTED]@", out)
        return out

    # ------------------------------------------------------- status reporting (Phase 2)
    def post_commit_status(
        self,
        workspace: str,
        repo: str,
        commit: str,
        state: str,
        key: str,
        name: str,
        description: str,
        url: str = "",
    ) -> None:
        workspace = _validate_component(workspace, "workspace")
        repo = _validate_component(repo, "repository")
        if not re.fullmatch(r"[0-9a-fA-F]{40}", commit or ""):
            raise BitbucketError("invalid commit SHA")
        payload = {
            "state": state,  # SUCCESSFUL | FAILED | INPROGRESS | STOPPED
            "key": key,
            "name": name,
            "description": description,
            "url": url,
        }
        resp = self._client.post(
            f"/repositories/{workspace}/{repo}/commit/{commit}/statuses/build", json=payload
        )
        if resp.status_code >= 400:
            raise BitbucketError(f"Failed to post build status: {resp.status_code} {resp.text[:300]}")


def _reject_worktree_symlinks(dest: str) -> None:
    for root, dirs, files in os.walk(dest, followlinks=False):
        for name in [*dirs, *files]:
            path = os.path.join(root, name)
            if os.path.islink(path):
                raise BitbucketError(f"repository contains unsupported symlink: {name}")


def _write_askpass(token: str) -> str:
    """Write a temporary mode-0600 GIT_ASKPASS script returning the token.

    The script answers the username prompt with ``x-token-auth`` and any
    other (password) prompt with the token. The file lives under /tmp and
    is removed by the caller in a finally block.
    """
    import tempfile

    fd, path = tempfile.mkstemp(prefix="sdt-askpass-", suffix=".sh")
    try:
        # The helper contains no token; the owner-only sidecar holds it.
        script = (
            "#!/bin/sh\n"
            'case "$1" in\n'
            "  *sername*) echo x-token-auth ;;\n"
            "  *) cat \"$0.token\" ;;\n"
            "esac\n"
        )
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(script)
        token_path = path + ".token"
        token_fd = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(token_fd, "w", encoding="utf-8") as fh:
            fh.write(token or "")
        os.chmod(path, 0o700)
        # Restrict the credential sidecar to the owner at creation time and
        # retain the executable helper's owner-only mode.
        os.chmod(token_path, 0o600)
        st = os.stat(path)
        if st.st_mode & 0o077:
            os.chmod(path, 0o700)
    except Exception:
        _remove_askpass(path)
        raise
    return path


def _remove_askpass(path: str | None) -> None:
    for candidate in (path or "", (path or "") + ".token"):
        if not candidate:
            continue
        try:
            os.remove(candidate)
        except OSError:
            pass


def _scrub_git_config(dest: str, token: str) -> None:
    """Remove any persisted credential from the fresh clone's config."""
    if not dest or not token:
        return
    cfg = os.path.join(dest, ".git", "config")
    try:
        with open(cfg, "r", encoding="utf-8", errors="replace") as fh:
            data = fh.read()
    except OSError:
        return
    if token not in data and "x-token-auth" not in data:
        return
    cleaned = data.replace(token, "")
    cleaned = re.sub(r"(https?://)[^@\s]*@", r"\1", cleaned)
    try:
        with open(cfg, "w", encoding="utf-8") as fh:
            fh.write(cleaned)
    except OSError:
        pass
def safe_slug(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]", "", value).lower()
