"""
Cookie Security Analyzer
Author: ARIF
"""

import asyncio
import logging
import re
from typing import List, Optional, Dict
from core.engine import Vulnerability, Severity
from core.requester import Requester


class CookieScanner:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.requester = Requester(config)
        self.vulnerabilities = []
        self.results_lock = asyncio.Lock()

    async def scan(self, target: str) -> List[Vulnerability]:
        self.logger.info(f"Starting Cookie Security analysis on {target}")
        self.vulnerabilities = []
        try:
            response = await self.requester.get(target)
            if not response:
                return self.vulnerabilities
            headers = {k.lower(): v for k, v in response.headers.items()}
            set_cookies = headers.get('set-cookie', '')

            if not set_cookies:
                return self.vulnerabilities

            cookie_entries = re.split(r'\n|,(?=\s*\w+=)', set_cookies)
            for entry in cookie_entries:
                if not entry.strip():
                    continue
                await self._analyze_cookie(entry.strip(), target)

        except Exception as e:
            self.logger.error(f"Cookie analysis error on {target}: {e}")
        return self.vulnerabilities

    async def _analyze_cookie(self, cookie_header: str, url: str) -> None:
        try:
            parts = cookie_header.split(';')
            cookie_name = parts[0].split('=')[0].strip() if '=' in parts[0] else "unknown"
            flags = [p.strip().lower() for p in parts[1:]]

            has_secure = 'secure' in flags
            has_httponly = 'httponly' in flags
            has_samesite = any('samesite' in f for f in flags)
            samesite_value = ""
            for f in flags:
                if 'samesite' in f:
                    if '=' in f:
                        samesite_value = f.split('=')[1].strip()
                    else:
                        samesite_value = "true"

            issues = []
            if not has_secure:
                issues.append(("Missing Secure flag", Severity.HIGH,
                               "Cookie sent over unencrypted HTTP connections"))
            if not has_httponly:
                issues.append(("Missing HttpOnly flag", Severity.MEDIUM,
                               "Cookie accessible via JavaScript (XSS risk)"))
            if has_samesite:
                if samesite_value.lower() == 'none':
                    issues.append(("SameSite=None", Severity.MEDIUM,
                                   "Cookie sent on cross-site requests"))
            else:
                issues.append(("Missing SameSite flag", Severity.LOW,
                               "Default SameSite behavior may be Lax or None"))

            for issue_name, severity, desc in issues:
                vuln = Vulnerability(
                    name=f"Cookie Security - {issue_name}",
                    description=f"Cookie '{cookie_name}': {desc}",
                    severity=severity,
                    url=url,
                    parameter=f"Set-Cookie: {cookie_name}",
                    payload=f"Set-Cookie: {cookie_header[:100]}",
                    evidence=f"Cookie flags: {', '.join(flags) if flags else 'none'}",
                    remediation=f"Set {issue_name.split(' ')[0] if not has_secure else 'the missing'} flag{'s' if not has_secure else ''} on cookie '{cookie_name}'.",
                    cvss_score=severity.score,
                    confidence=0.95,
                    module="cookie"
                )
                async with self.results_lock:
                    self.vulnerabilities.append(vuln)

        except Exception as e:
            self.logger.debug(f"Cookie analysis error: {e}")
