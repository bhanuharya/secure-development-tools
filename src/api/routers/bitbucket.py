from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Query

from src.integrations.bitbucket_client import BitbucketClient, BitbucketError

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/bitbucket", tags=["bitbucket"])


def _client() -> BitbucketClient:
    try:
        return BitbucketClient()
    except BitbucketError as exc:
        raise HTTPException(503, str(exc)) from exc


@router.get("/{workspace}/repos")
def list_repos(workspace: str, cursor: str | None = Query(None), page_len: int = Query(100, ge=1, le=100)):
    try:
        page = _client().list_repos(workspace, cursor=cursor, page_len=page_len)
    except BitbucketError as exc:
        raise HTTPException(502, str(exc)) from exc
    repos = [
        {"slug": r.get("slug"), "name": r.get("name"), "language": r.get("language"),
         "project": (r.get("project") or {}).get("key"), "description": (r.get("description") or "")[:200]}
        for r in page.values
    ]
    return {"repos": repos, "next": page.next_cursor, "workspace": workspace}


@router.get("/{workspace}/{repo}/branches")
def list_branches(workspace: str, repo: str, cursor: str | None = Query(None), page_len: int = Query(100, ge=1, le=100)):
    try:
        page = _client().list_branches(workspace, repo, cursor=cursor, page_len=page_len)
    except BitbucketError as exc:
        raise HTTPException(502, str(exc)) from exc
    branches = [
        {"name": b.get("name"), "hash": (b.get("target") or {}).get("hash", ""),
         "message": ((b.get("target") or {}).get("message") or "")[:100]}
        for b in page.values
    ]
    return {"branches": branches, "next": page.next_cursor}


@router.get("/{workspace}/{repo}/pullrequests")
def list_pull_requests(workspace: str, repo: str):
    try:
        prs = _client().list_pull_requests(workspace, repo, state="OPEN")
    except BitbucketError as exc:
        raise HTTPException(502, str(exc)) from exc
    return {
        "pullrequests": [
            {
                "id": pr.get("id"),
                "title": pr.get("title"),
                "state": pr.get("state"),
                "source": (pr.get("source") or {}).get("branch", {}).get("name"),
                "destination": (pr.get("destination") or {}).get("branch", {}).get("name"),
                "author": (pr.get("author") or {}).get("display_name", ""),
                "links": (pr.get("links") or {}).get("html", {}).get("href"),
            }
            for pr in prs
        ]
    }
