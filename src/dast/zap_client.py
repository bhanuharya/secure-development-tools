from __future__ import annotations

import logging
import re
import time
from typing import Callable

import httpx

from src.config import ZAP_API_KEY, ZAP_API_URL
from src.scanners.base import RawFinding

log = logging.getLogger(__name__)

_RISK_TO_SEVERITY = {0: "info", 1: "low", 2: "medium", 3: "high"}

ProgressFn = Callable[[str, int, str], None]  # (stage, percent, note)


class ZapError(Exception):
    pass


class ZapClient:
    """Thin client over the ZAP daemon JSON API (spider + active scan + auth)."""

    def __init__(self, base_url: str = ZAP_API_URL, api_key: str = ZAP_API_KEY, timeout: float = 60.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self._http = httpx.Client(timeout=timeout)
        self._params = {"apikey": api_key} if api_key else {}

    # ------------------------------------------------------------------ utils
    def available(self) -> bool:
        try:
            resp = self._http.get(f"{self.base_url}/JSON/core/view/version", params=self._params, timeout=5)
            return resp.status_code == 200 and "version" in resp.text
        except httpx.HTTPError:
            return False

    def _get_json(self, endpoint: str, params: dict | None = None) -> dict:
        resp = self._http.get(f"{self.base_url}{endpoint}", params={**self._params, **(params or {})})
        if resp.status_code != 200:
            raise ZapError(f"ZAP {endpoint} -> {resp.status_code}: {resp.text[:200]}")
        return resp.json()

    def _post(self, endpoint: str, params: dict | None = None) -> dict:
        resp = self._http.post(f"{self.base_url}{endpoint}", data={**self._params, **(params or {})})
        if resp.status_code != 200:
            raise ZapError(f"ZAP POST {endpoint} -> {resp.status_code}: {resp.text[:200]}")
        data = resp.json()
        result = data.get("Result") or data.get("result")
        if isinstance(result, str) and result.startswith("ERROR"):
            raise ZapError(f"ZAP {endpoint} failed: {result}")
        return data

    def _wait_scan(self, view_path: str, scan_id: str, stage: str, on_progress: ProgressFn) -> None:
        last_pct = -1
        while True:
            data = self._get_json(view_path, {"scanId": scan_id})
            status = data.get("status")
            try:
                pct = int(status) if status is not None else 0
            except (TypeError, ValueError):
                pct = 0
            if pct != last_pct:
                on_progress(stage, pct, "")
                last_pct = pct
            if pct >= 100:
                return
            time.sleep(2)

    # ------------------------------------------------------------------ run
    def run_dast(
        self,
        *,
        scan_id: int,
        target_url: str,
        auth_mode: str = "none",
        login_url: str = "",
        username_field: str = "",
        password_field: str = "",
        auth_username: str = "",
        auth_password: str = "",
        context_file_path: str = "",
        on_progress: ProgressFn | None = None,
    ) -> list[RawFinding]:
        prog = on_progress or (lambda *a, **k: None)
        context_name = f"scp-scan-{scan_id}"
        context_id: int | None = None

        # --- context + auth -------------------------------------------------
        if auth_mode == "context_file":
            resp = self._post("/JSON/context/action/importContext", {"file": context_file_path})
            context_id = _first_int(resp.get("contextId"))
            prog("setup", 5, "imported ZAP context file")
        else:
            resp = self._post("/JSON/context/action/newContext", {"contextName": context_name})
            context_id = _first_int(resp.get("contextId"))
            prog("setup", 10, "created scan context")
            if auth_mode == "form":
                self._configure_form_auth(
                    context_id=context_id,
                    context_name=context_name,
                    target_url=target_url,
                    login_url=login_url,
                    username_field=username_field,
                    password_field=password_field,
                    auth_username=auth_username,
                    auth_password=auth_password,
                )
                prog("setup", 25, "form-login auth configured")
            else:
                self._post("/JSON/sessionManagement/action/setSessionManagementMethod",
                           {"contextId": context_id, "sessionManagementMethodName": "cookieBasedSessionManagement"})

        # put the target in scope
        self._post("/JSON/context/action/includeInContext",
                   {"contextName": context_name, "regex": re.escape(target_url)})
        prog("setup", 30, "target in scope")

        # --- spider -----------------------------------------------------------
        if context_id is not None and auth_mode != "none":
            spider = self._post("/JSON/spider/action/scanAsUser", {
                "url": target_url, "contextId": context_id, "maxChildren": 10, "recurse": True,
            })
        else:
            spider = self._post("/JSON/spider/action/scan", {
                "url": target_url, "maxChildren": 10, "recurse": True, "contextName": context_name,
            })
        self._wait_scan("/JSON/spider/view/status", str(_first_int(spider.get("scanId"))), "spider", prog)

        # --- active scan -------------------------------------------------------
        if context_id is not None and auth_mode != "none":
            ascan = self._post("/JSON/ascan/action/scanAsUser", {
                "url": target_url, "contextId": context_id, "recurse": True, "inScopeOnly": True,
            })
        else:
            ascan = self._post("/JSON/ascan/action/scan", {
                "url": target_url, "recurse": True, "inScopeOnly": True, "contextName": context_name,
            })
        self._wait_scan("/JSON/ascan/view/status", str(_first_int(ascan.get("scanId"))), "active", prog)
        prog("active", 100, "active scan complete")

        # --- alerts --------------------------------------------------------------
        alerts = self._get_json("/JSON/core/view/alerts", {"baseurl": target_url}).get("alerts", [])
        return self._alerts_to_findings(alerts)

    # ------------------------------------------------------------------ auth
    def _configure_form_auth(
        self,
        *,
        context_id: int,
        context_name: str,
        target_url: str,
        login_url: str,
        username_field: str,
        password_field: str,
        auth_username: str,
        auth_password: str,
    ) -> None:
        auth_params = f"loginRequestUrl={_urlencode(login_url)}&loginPageUrl={_urlencode(target_url)}"
        self._post("/JSON/authentication/action/setAuthenticationMethod", {
            "contextId": context_id,
            "authenticationMethodName": "formBasedAuthentication",
            "authMethodConfigParams": auth_params,
        })
        # Field selectors are registered via the login request structure.
        self._post("/JSON/authentication/action/setLoginRequestConfiguration", {
            "contextId": context_id,
            "loginUrl": login_url,
            "loginRequestData": _urlencode(
                f"{username_field}=%username%&{password_field}=%password%"
            ),
        })
        # Create + configure the auth user
        user = self._post("/JSON/users/action/newUser", {"contextId": context_id, "name": auth_username or "scp-user"})
        user_id = _first_int(user.get("userId"))
        creds = f"username={_urlencode(auth_username)}&password={_urlencode(auth_password)}"
        self._post("/JSON/users/action/setAuthenticationCredentials", {
            "userId": user_id, "authCredentialsConfigParams": creds,
        })
        self._post("/JSON/users/action/setUserEnabled", {"userId": user_id, "enabled": True})
        self._post("/JSON/session/action/setActiveScanForUser", {"contextId": context_id, "userId": user_id})
        self._post("/JSON/sessionManagement/action/setSessionManagementMethod", {
            "contextId": context_id, "sessionManagementMethodName": "cookieBasedSessionManagement",
        })

    # ------------------------------------------------------------------ maps
    @staticmethod
    def _alerts_to_findings(alerts: list[dict]) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for a in alerts:
            risk = _first_int(a.get("risk"))
            cweid = a.get("cweid")
            url = a.get("url", "")
            param = a.get("param")
            findings.append(
                RawFinding(
                    tool="zap",
                    source_type="dast",
                    rule_id=a.get("pluginId") or a.get("alertRef", ""),
                    severity=_RISK_TO_SEVERITY.get(risk, "info"),
                    cwe=f"CWE-{cweid}" if cweid else "",
                    file_path=url,
                    snippet=f"{url}{f' (param: {param})' if param else ''}",
                    description=a.get("alert") or (a.get("description") or "")[:1500],
                    remediation=a.get("solution", ""),
                    raw=a,
                )
            )
        return findings


def _first_int(value) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _urlencode(value: str) -> str:
    from urllib.parse import quote

    return quote(value or "", safe="")
