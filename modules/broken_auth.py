"""
Broken Authentication Scanner
Author: ARIF
"""

import asyncio
import logging
import re
from typing import List, Optional, Dict
from urllib.parse import urlparse, urljoin
from core.engine import Vulnerability, Severity
from core.requester import Requester


class AuthScanner:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.requester = Requester(config)
        self.vulnerabilities = []
        self.results_lock = asyncio.Lock()

    async def scan(self, target: str) -> List[Vulnerability]:
        self.logger.info(f"Starting Broken Authentication scan on {target}")
        self.vulnerabilities = []
        try:
            response = await self.requester.get(target)
            if not response:
                return self.vulnerabilities
            html = await response.text()
            forms = await self.requester.extract_forms(target, html)
            headers = {k: v for k, v in response.headers.items()}

            tasks = []
            tasks.append(self._check_auth_forms(forms, target))
            tasks.append(self._check_login_endpoints(target))
            tasks.append(self._check_session_cookies(headers))
            tasks.append(self._check_weak_password_policy(target))

            await asyncio.gather(*tasks)
        except Exception as e:
            self.logger.error(f"Broken Auth scan error on {target}: {e}")
        return self.vulnerabilities

    async def _check_auth_forms(self, forms: List[Dict], base_url: str) -> None:
        for form in forms:
            inputs = [i.get("name", "").lower() for i in form.get("inputs", [])]
            input_types = [i.get("type", "") for i in form.get("inputs", [])]

            has_password = "password" in input_types
            if not has_password:
                continue

            issues = []
            if has_password and not self._check_csrf_in_form(form):
                issues.append("Login form lacks CSRF protection")
            if has_password and not self._check_https_action(form, base_url):
                issues.append("Login form submits over HTTP (not HTTPS)")

            for issue in issues:
                vuln = Vulnerability(
                    name="Broken Authentication",
                    description=issue,
                    severity=Severity.HIGH,
                    url=form.get("action", base_url),
                    parameter="login_form",
                    payload="N/A",
                    evidence=f"Form action: {form.get('action', 'N/A')}",
                    remediation="Use HTTPS, implement CSRF tokens, enforce strong password policies, implement account lockout.",
                    cvss_score=7.0,
                    confidence=0.8,
                    module="auth"
                )
                async with self.results_lock:
                    self.vulnerabilities.append(vuln)

    def _check_csrf_in_form(self, form: Dict) -> bool:
        csrf_patterns = ['csrf', 'token', '_token', 'xsrf']
        for inp in form.get("inputs", []):
            name_lower = inp.get("name", "").lower()
            for pattern in csrf_patterns:
                if pattern in name_lower:
                    return True
        return False

    def _check_https_action(self, form: Dict, base_url: str) -> bool:
        action = form.get("action", base_url)
        return action.startswith("https://")

    async def _check_login_endpoints(self, target: str) -> None:
        login_endpoints = ["/login", "/signin", "/auth", "/admin", "/wp-login.php",
                           "/administrator", "/user/login", "/login.aspx", "/Login"]
        for endpoint in login_endpoints:
            try:
                url = urljoin(target, endpoint)
                response = await self.requester.get(url)
                if response and response.status == 200:
                    html = await response.text()
                    if re.search(r'(password|passwd|pwd)', html, re.IGNORECASE):
                        vuln = Vulnerability(
                            name="Login Endpoint Exposed",
                            description=f"Login endpoint found at {endpoint}",
                            severity=Severity.INFO,
                            url=url,
                            parameter="N/A",
                            payload="N/A",
                            evidence=f"Login form detected at {endpoint}",
                            remediation="Ensure login page uses HTTPS, rate limiting, and account lockout mechanisms.",
                            cvss_score=0.0,
                            confidence=1.0,
                            module="auth"
                        )
                        async with self.results_lock:
                            self.vulnerabilities.append(vuln)
            except Exception:
                pass

    async def _check_session_cookies(self, headers: Dict) -> None:
        set_cookie = headers.get('Set-Cookie', '')
        if not set_cookie:
            return
        for cookie_part in set_cookie.split('\n'):
            if cookie_part.strip():
                if 'secure' not in cookie_part.lower():
                    vuln = Vulnerability(
                        name="Session Cookie Missing Secure Flag",
                        description="Session cookie can be transmitted over unencrypted HTTP",
                        severity=Severity.HIGH,
                        url="N/A",
                        parameter="Session Cookie",
                        payload="N/A",
                        evidence=f"Set-Cookie header missing Secure flag: {cookie_part[:100]}",
                        remediation="Set Secure, HttpOnly, and SameSite=Strict flags on session cookies.",
                        cvss_score=6.5,
                        confidence=0.95,
                        module="auth"
                    )
                    async with self.results_lock:
                        self.vulnerabilities.append(vuln)
                if 'httponly' not in cookie_part.lower():
                    vuln = Vulnerability(
                        name="Session Cookie Missing HttpOnly Flag",
                        description="Session cookie accessible via JavaScript (XSS risk)",
                        severity=Severity.MEDIUM,
                        url="N/A",
                        parameter="Session Cookie",
                        payload="N/A",
                        evidence=f"Set-Cookie header missing HttpOnly flag",
                        remediation="Set HttpOnly flag on session cookies.",
                        cvss_score=4.3,
                        confidence=0.9,
                        module="auth"
                    )
                    async with self.results_lock:
                        self.vulnerabilities.append(vuln)

    async def _check_weak_password_policy(self, target: str) -> None:
        common_passwords = [
            "admin", "password", "123456", "12345678", "qwerty",
            "admin123", "letmein", "welcome", "monkey", "dragon"
        ]
        for endpoint in ["/register", "/signup", "/user/register", "/wp-login.php?action=register"]:
            url = urljoin(target, endpoint)
            resp = await self.requester.get(url)
            if resp:
                html = await resp.text()
                if "password" in html.lower() and ("min" in html.lower() or "character" in html.lower()):
                    match = re.search(r'(\d+)\s*(?:character|char|min|length)', html, re.IGNORECASE)
                    if not match or int(match.group(1)) < 8:
                        vuln = Vulnerability(
                            name="Weak Password Policy",
                            description="Password policy does not enforce minimum length (8+ characters) or complexity",
                            severity=Severity.MEDIUM,
                            url=url,
                            parameter="password_policy",
                            payload="N/A",
                            evidence=f"Password policy allows short/weak passwords",
                            remediation="Enforce minimum 8 characters, require uppercase, lowercase, digits, and special characters.",
                            cvss_score=5.5,
                            confidence=0.7,
                            module="auth"
                        )
                        async with self.results_lock:
                            self.vulnerabilities.append(vuln)
                    break
