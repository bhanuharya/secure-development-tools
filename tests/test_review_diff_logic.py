"""Unit tests for Milestone 3 logic-abuse enhancements in tools/sdt_review_diff.py.

Runnable with either pytest or plain `python3 -m unittest tests/test_review_diff_logic.py`
(no third-party dependencies required).
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent.parent / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import sdt_review_diff  # noqa: E402


SAMPLE_DIFF = """@@ -8,5 +8,6 @@
 router.get('/health', health)
-router.get('/reports/:id', auth, owner, showReport)
+router.get('/reports/:id', auth, showReport)
+router.delete('/reports/:id', auth, deleteReport)
 module.exports = router
"""


class TestReviewDiffLogicAbuse(unittest.TestCase):
    def test_backwards_compatible_legacy_finding_shape(self):
        finding = {
            "path": "routes/report.js",
            "line": 9,
            "title": "Owner check removed",
            "severity": "high",
            "confidence": "high",
            "evidence": "Line 9 drops owner middleware.",
            "check": "confirm showReport checks owner",
            "fix": "restore owner middleware",
        }

        def call(codex, model, prompt, timeout, schema):
            return {"findings": [finding, {**finding, "line": 8}]}

        report = sdt_review_diff.review(
            {"routes/report.js": SAMPLE_DIFF},
            "codex",
            "gpt-6.1-sol",
            per_call_timeout=30,
            budget=300,
            call=call,
        )
        self.assertEqual([(f["path"], f["line"]) for f in report["findings"]], [("routes/report.js", 9)])
        md = sdt_review_diff.markdown(report, "origin/main", 1)
        self.assertIn("## 1. Owner check removed", md)

    def test_enriches_prompt_with_routes_invariants_and_callees(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "payments").mkdir()
            (root / "payments" / "payout.py").write_text(
                "def approve_payout(req, payout_id):\n"
                "    return _apply_payout(payout_id)\n",
                encoding="utf-8",
            )
            (root / "payments" / "service.py").write_text(
                "def _apply_payout(payout_id):\n"
                "    api_key = 'sk_live_0123456789abcdefghij'\n"
                "    return db.execute('UPDATE payouts SET status=\"APPROVED\" WHERE id=?', payout_id)\n",
                encoding="utf-8",
            )
            (root / ".secure-dev").mkdir()
            (root / ".secure-dev" / "invariants.yaml").write_text(
                "apiVersion: secure-dev/invariants/v1alpha1\n"
                "kind: SecurityInvariants\n"
                "domainInvariants:\n"
                "  - id: dual-control-payout\n"
                "    paths: [\"payments/**\"]\n"
                "    abuseClasses: [\"maker-checker\", \"state-machine\"]\n"
                "    statement: >-\n"
                "      Payout approval must verify approverId != creatorId and status == PENDING.\n"
                "    severity: high\n",
                encoding="utf-8",
            )
            ep_path = root / "endpoints.json"
            ep_path.write_text(json.dumps({
                "schema": "sdt-endpoints/v1",
                "routes": [{
                    "service": ".",
                    "framework": "fastapi",
                    "method": "POST",
                    "path": "/api/v1/payouts/{payout_id}/approve",
                    "handler": "approve_payout",
                    "file": "payments/payout.py",
                    "line": 1,
                    "protection": "authenticated",
                    "roles": [],
                }],
            }), encoding="utf-8")

            routes = sdt_review_diff.load_endpoint_context(ep_path)
            invs = sdt_review_diff.load_domain_invariants(root)
            self.assertEqual(len(invs), 1)
            self.assertEqual(invs[0]["id"], "dual-control-payout")

            diff = "@@ -1,1 +1,2 @@\n def approve_payout(req, payout_id):\n+    return _apply_payout(payout_id)\n"
            prompts: list[str] = []

            def call(codex, model, prompt, timeout, schema):
                prompts.append(prompt)
                return {"findings": [{
                    "path": "payments/payout.py",
                    "line": 2,
                    "title": "Payout approval skips maker-checker and prior-state validation",
                    "severity": "high",
                    "confidence": "high",
                    "abuse_class": "maker-checker",
                    "attack_scenario": "Any authenticated user approves their own payout in one POST.",
                    "evidence": "Line 2 calls _apply_payout which sets APPROVED unconditionally.",
                    "check": "Verify _apply_payout checks creatorId != current_user and status == PENDING.",
                    "fix": "Require FINANCE_ADMIN role and check creator_id != actor_id and status == PENDING.",
                }]}

            report = sdt_review_diff.review(
                {"payments/payout.py": diff},
                "codex",
                "gpt-6.1-sol",
                per_call_timeout=30,
                budget=300,
                call=call,
                src_root=root,
                routes_by_file=routes,
                invariants=invs,
            )
            self.assertEqual(len(prompts), 1)
            prompt = prompts[0]
            self.assertIn("Resolved HTTP routes in this file", prompt)
            self.assertIn("POST /api/v1/payouts/{payout_id}/approve", prompt)
            self.assertIn("dual-control-payout", prompt)
            self.assertIn("approverId != creatorId", prompt)
            self.assertIn("def _apply_payout(payout_id):", prompt)
            # Secrets inside 1-hop callee snippets must be redacted before egress!
            self.assertNotIn("sk_live_0123456789abcdefghij", prompt)
            self.assertIn("[REDACTED]", prompt)

            md = sdt_review_diff.markdown(report, "origin/main", 0)
            self.assertIn("[maker-checker]", md)
            self.assertIn("**Attack scenario:**", md)

    def test_risk_weighted_ordering_and_sceptical_verifier(self):
        invs = [{"id": "payout-inv", "paths": ["z_payments/**"], "statement": "Check maker-checker."}]
        diffs = {
            "a_utils/strings.py": "@@ -1,1 +1,2 @@\n def trim(s):\n+    return s.strip()\n",
            "z_payments/payout.py": "@@ -1,2 +1,2 @@\n-    require_admin(user)\n+    approve(payout_id)\n",
        }
        seen_order: list[str] = []
        call_num = 0

        def call(codex, model, prompt, timeout, schema):
            nonlocal call_num
            call_num += 1
            if call_num == 1:
                # Verify z_payments/payout.py appears BEFORE a_utils/strings.py in the prompt.
                self.assertLess(prompt.index("### z_payments/payout.py"), prompt.index("### a_utils/strings.py"))
                seen_order.append("review")
                return {"findings": [
                    {
                        "path": "z_payments/payout.py", "line": 1,
                        "title": "Admin check removed from payout approval",
                        "severity": "high", "confidence": "high",
                        "abuse_class": "bfla-authz",
                        "attack_scenario": "Non-admin user calls approve() directly.",
                        "evidence": "Line 1 drops require_admin(user).",
                        "check": "Check middleware", "fix": "Restore require_admin(user)",
                    },
                    {
                        "path": "a_utils/strings.py", "line": 2,
                        "title": "Speculative whitespace issue",
                        "severity": "medium", "confidence": "low",
                        "abuse_class": "other",
                        "attack_scenario": "Maybe trims something.",
                        "evidence": "Line 2 calls strip().",
                        "check": "Check callers", "fix": "None",
                    },
                ]}
            seen_order.append("verify")
            return {"decisions": [
                {"index": 0, "exploitable": True, "reason": "require_admin was removed"},
                {"index": 1, "exploitable": False, "reason": "strip() is not exploitable"},
            ]}

        report = sdt_review_diff.review(
            diffs,
            "codex",
            "gpt-6.1-sol",
            per_call_timeout=30,
            budget=300,
            call=call,
            invariants=invs,
            verify=True,
        )
        self.assertEqual(seen_order, ["review", "verify"])
        self.assertEqual(report["dropped_by_verifier"], 1)
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["path"], "z_payments/payout.py")
        self.assertTrue(report["findings"][0]["verified"])
        md = sdt_review_diff.markdown(report, "origin/main", 0)
        self.assertIn("dismissed 1 speculative candidate(s)", md)
        self.assertIn("verified", md)

    def test_verifier_omitted_finding_stays_unverified(self):
        diffs = {
            "payments/payout.py": "@@ -1,2 +1,3 @@\n-    require_admin(user)\n+    approve(payout_id)\n+    refund(order_id)\n",
        }
        call_num = 0

        def call(codex, model, prompt, timeout, schema):
            nonlocal call_num
            call_num += 1
            if call_num == 1:
                return {"findings": [
                    {
                        "path": "payments/payout.py", "line": 1,
                        "title": "Admin check removed from approve",
                        "severity": "high", "confidence": "high",
                        "evidence": "Line 1 drops require_admin.",
                        "check": "Check middleware", "fix": "Restore require_admin",
                    },
                    {
                        "path": "payments/payout.py", "line": 2,
                        "title": "Unchecked refund call",
                        "severity": "medium", "confidence": "medium",
                        "evidence": "Line 2 calls refund without state check.",
                        "check": "Check refund state", "fix": "Check status == PAID",
                    },
                ]}
            # Verifier only answers index 0 and omits index 1.
            return {"decisions": [
                {"index": 0, "exploitable": True, "reason": "confirmed"},
            ]}

        report = sdt_review_diff.review(
            diffs, "codex", "gpt-6.1-sol",
            per_call_timeout=30, budget=300, call=call, verify=True,
        )
        self.assertEqual(report["dropped_by_verifier"], 0)
        self.assertEqual(len(report["findings"]), 2)
        by_line = {f["line"]: f for f in report["findings"]}
        self.assertTrue(by_line[1].get("verified"))
        self.assertFalse(by_line[2].get("verified", False))
        md = sdt_review_diff.markdown(report, "origin/main", 0)
        self.assertIn("(confidence high) · verified", md)
        self.assertNotIn("(confidence medium) · verified", md)


OTHER_DIFF = """@@ -1,2 +1,3 @@
 const db = require('./db')
+const limit = 50
 module.exports = db
"""

CHANGED_DIFF = """@@ -8,5 +8,7 @@
 router.get('/health', health)
-router.get('/reports/:id', auth, owner, showReport)
+router.get('/reports/:id', auth, showReport)
+router.delete('/reports/:id', auth, deleteReport)
+router.patch('/reports/:id', auth, renameReport)
 module.exports = router
"""

OWNER_FINDING = {
    "path": "routes/report.js", "line": 9, "title": "Owner check removed", "severity": "high",
    "confidence": "high", "abuse_class": "bola-idor", "attack_scenario": "Any user reads another user's report.",
    "evidence": "Line 9 drops the owner middleware.", "check": "showReport", "fix": "restore owner",
}


class TestReviewMemory(unittest.TestCase):
    """A rescan reads the same: the model is asked again only about files whose change changed."""

    def run_review(self, diffs, call, memory, scope="pr-1", verify=False):
        return sdt_review_diff.review(diffs, "codex", "gpt-6.1-sol", per_call_timeout=30, budget=300,
                                      call=call, memory=memory, scope=scope, verify=verify)

    def test_unchanged_change_is_not_asked_again_and_reads_the_same(self):
        prompts = []

        def call(codex, model, prompt, timeout, schema):
            prompts.append(prompt)  # the model words its answer differently every time
            return {"findings": [{**OWNER_FINDING, "title": f"Owner check removed (wording {len(prompts)})"}]}

        memory: dict = {}
        first = self.run_review({"routes/report.js": SAMPLE_DIFF}, call, memory)
        second = self.run_review({"routes/report.js": SAMPLE_DIFF}, call, memory)
        self.assertEqual(len(prompts), 1)
        self.assertEqual(first["findings"], second["findings"])
        self.assertEqual(second["files_remembered"], ["routes/report.js"])
        self.assertEqual(second["files_reviewed"], ["routes/report.js"])
        self.assertIn("unchanged since an earlier review", sdt_review_diff.markdown(second, "origin/main", 0))

    def test_changed_file_is_asked_with_its_earlier_titles_and_the_rest_is_reused(self):
        prompts = []

        def call(codex, model, prompt, timeout, schema):
            prompts.append(prompt)
            return {"findings": [OWNER_FINDING] if "### routes/report.js" in prompt else []}

        memory: dict = {}
        self.run_review({"routes/report.js": SAMPLE_DIFF, "lib/other.js": OTHER_DIFF}, call, memory)
        calls_before = len(prompts)
        self.run_review({"routes/report.js": CHANGED_DIFF, "lib/other.js": OTHER_DIFF}, call, memory)
        new_prompts = prompts[calls_before:]
        self.assertEqual(len(new_prompts), 1)
        self.assertIn("### routes/report.js", new_prompts[0])
        self.assertNotIn("### lib/other.js", new_prompts[0])
        self.assertIn("An earlier review of this file in this pull request", new_prompts[0])
        self.assertIn("(high) Owner check removed [was line 9]", new_prompts[0])

    def test_earlier_titles_stay_within_their_pull_request(self):
        prompts = []

        def call(codex, model, prompt, timeout, schema):
            prompts.append(prompt)
            return {"findings": [OWNER_FINDING]}

        memory: dict = {}
        self.run_review({"routes/report.js": SAMPLE_DIFF}, call, memory, scope="pr-1")
        self.run_review({"routes/report.js": CHANGED_DIFF}, call, memory, scope="pr-2")
        self.assertEqual(len(prompts), 2)
        self.assertNotIn("An earlier review", prompts[1])

    def test_failed_call_is_asked_again_next_time(self):
        answers = [RuntimeError("codex exited 1"), {"findings": [OWNER_FINDING]}]

        def call(codex, model, prompt, timeout, schema):
            answer = answers.pop(0)
            if isinstance(answer, Exception):
                raise answer
            return answer

        memory: dict = {}
        first = self.run_review({"routes/report.js": SAMPLE_DIFF}, call, memory)
        self.assertEqual((first["failed_calls"], memory), (1, {}))
        second = self.run_review({"routes/report.js": SAMPLE_DIFF}, call, memory)
        self.assertEqual([f["title"] for f in second["findings"]], ["Owner check removed"])
        self.assertEqual(len(memory), 1)

    def test_memory_file_drops_old_reviews_and_redacts_values(self):
        value = "Zk81" + "mQ7vT2pL9xR4"
        memory = {
            "sha256:recent": {"path": "a.js", "scope": "pr-1", "used": "2026-11-20", "saved": "2026-11-20T00:00:00+00:00",
                              "findings": [{**OWNER_FINDING, "path": "a.js", "evidence": f'password = "{value}" on line 9'}]},
            "sha256:old": {"path": "b.js", "scope": "pr-1", "used": "2026-01-01", "saved": "2026-01-01T00:00:00+00:00",
                           "findings": []},
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state" / "repo.json"
            sdt_review_diff.save_memory(path, memory, "2026-11-24")
            self.assertNotIn(value, path.read_text())
            loaded = sdt_review_diff.load_memory(path)
        self.assertEqual(list(loaded), ["sha256:recent"])
        self.assertIn("[REDACTED]", loaded["sha256:recent"]["findings"][0]["evidence"])

    def test_default_memory_path_follows_the_state_directory(self):
        self.assertEqual(sdt_review_diff.default_memory_path("ws_my repo", {"SDT_STATE_DIR": "/state"}),
                         Path("/state/ai-change-review/ws_my_repo.json"))
        self.assertEqual(sdt_review_diff.default_memory_path("x", {"SDT_DIFF_REVIEW_MEMORY": "/m.json"}), Path("/m.json"))


if __name__ == "__main__":
    unittest.main()
