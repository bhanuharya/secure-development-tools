import httpx
import pytest

from src.integrations.bitbucket_client import BitbucketClient, BitbucketError
from src.integrations.diff_parser import parse_diff

FIXTURE_DIFF = """
diff --git a/app.py b/app.py
index 1a2b3c4..5d6e7f8 100644
--- a/app.py
+++ b/app.py
@@ -5,15 +5,4 @@
 def login(user, password):
     digest = hashlib.md5(password.encode()).hexdigest()
     conn = sqlite3.connect("app.db")
     cur = conn.cursor()
     query = "SELECT * FROM users WHERE user = '" + user + "'"
     cur.execute(query)
-    return digest + str(cur.fetchall())
+    return str(cur.fetchall())
 
 
 def session_token():
     return eval("lambda: 'static-token'")
 
 
 def get_api_key():
     return "sk_live_2f7dNn3Ke8Qb0HkLm9XpRq1ZvYw3AtC5"
""".strip()


def mock_client(pages) -> BitbucketClient:
    """pages: callable(request) -> (status_code, json)."""
    transport = httpx.MockTransport(pages)
    client = BitbucketClient.__new__(BitbucketClient)
    client._client = httpx.Client(base_url="https://api.bitbucket.org/2.0", transport=transport)
    return client


def test_list_repos_pagination():
    def handler(request):
        if request.url.query.decode().startswith("cursor=2"):
            return httpx.Response(200, json={"values": [{"slug": "repo3"}], "pagelen": 2})
        return httpx.Response(
            200,
            json={
                "values": [{"slug": "repo1"}, {"slug": "repo2"}],
                "pagelen": 2,
                "next": "https://api.bitbucket.org/2.0/repositories/ws?pagelen=2&cursor=2",
            },
        )

    client = mock_client(handler)
    page1 = client.list_repos("ws", page_len=2)
    assert [r["slug"] for r in page1.values] == ["repo1", "repo2"]
    assert page1.next_cursor == "/repositories/ws?pagelen=2&cursor=2"
    page2 = client.list_repos("ws", cursor=page1.next_cursor, page_len=2)
    assert [r["slug"] for r in page2.values] == ["repo3"]
    assert page2.next_cursor is None


def test_list_pull_requests_filters_open():
    def handler(request):
        return httpx.Response(
            200,
            json={
                "values": [
                    {"id": 1, "state": "OPEN"},
                    {"id": 2, "state": "MERGED"},
                    {"id": 3, "state": "OPEN"},
                ]
            },
        )

    client = mock_client(handler)
    prs = client.list_pull_requests("ws", "repo")
    assert {p["id"] for p in prs} == {1, 3}


def test_clone_url_token_injection():
    client = BitbucketClient.__new__(BitbucketClient)
    client.token = "secret-token"
    url = client.repo_clone_url("miraworkspace", "order-service")
    assert url == "https://x-token-auth:secret-token@bitbucket.org/miraworkspace/order-service.git"


def test_401_raises():
    def handler(request):
        return httpx.Response(401, json={"error": {"message": "bad creds"}})

    client = mock_client(handler)
    with pytest.raises(BitbucketError, match="401"):
        client.get_repo("ws", "r")


def test_diff_parser_ranges():
    parsed = parse_diff(FIXTURE_DIFF)
    assert "app.py" in parsed.files
    ranges = parsed.files["app.py"]
    # lines 5..11 context and 14..19 (includes removals/resumes) coalesced to spans
    assert ranges[0].start == 5
    assert any(r.contains(6) for r in ranges)
    assert any(r.contains(9) for r in ranges)
    assert any(r.contains(15) for r in ranges)
    assert any(r.contains(19) for r in ranges)
    assert not any(r.contains(2) for r in ranges)
    assert parsed.is_line_changed("app.py", 9) is True
    assert parsed.is_line_changed("app.py", 2) is False
    assert parsed.is_line_changed("app.py", None) is False
    assert parsed.is_line_changed("other.py", 9) is False


def test_diff_parser_binary_files_skipped():
    diff = "diff --git a/favicon.ico b/favicon.ico\nBinary files differ\n"
    parsed = parse_diff(diff)
    assert "favicon.ico" not in parsed.files