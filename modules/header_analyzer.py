"""
Security Header Analyzer — HSTS, CSP, XFO, XXP, CT
Author: ARIF
"""

import asyncio
import logging
from typing import List, Optional, Dict
from core.engine import Vulnerability, Severity
from core.requester import Requester


class HeadersScanner:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.requester = Requester(config)
        self.vulnerabilities = []
        self.results_lock = asyncio.Lock()

    async def scan(self, target: str) -> List[Vulnerability]:
        self.logger.info(f"Starting Security Header analysis on {target}")
        self.vulnerabilities = []

        try:
            response = await self.requester.get(target)
            if not response:
                return self.vulnerabilities

            headers = {}
            for k, v in response.headers.items():
                headers[k.lower()] = v

            await self._check_hsts(headers, target)
            await self._check_csp(headers, target)
            await self._check_xframe(headers, target)
            await self._check_xxp(headers, target)
            await self._check_content_type(headers, target)
            await self._check_referrer_policy(headers, target)
            await self._check_permissions_policy(headers, target)
            await self._check_feature_policy(headers, target)

        except Exception as e:
            self.logger.error(f"Header analysis error on {target}: {e}")

        return self.vulnerabilities

    async def _check_hsts(self, headers: Dict[str, str], url: str) -> None:
        hsts = headers.get('strict-transport-security', '')
        if not hsts:
            vuln = Vulnerability(
                name="Missing HSTS Header",
                description="HTTP Strict-Transport-Security header is missing. Site is vulnerable to SSL stripping attacks.",
                severity=Severity.MEDIUM,
                url=url,
                parameter="Strict-Transport-Security",
                payload="Missing",
                evidence="HSTS header not present in response",
                remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' header.",
                cvss_score=5.0,
                confidence=1.0,
                module="headers"
            )
            async with self.results_lock:
                self.vulnerabilities.append(vuln)
        else:
            if 'max-age=' in hsts:
                import re
                match = re.search(r'max-age=(\d+)', hsts)
                if match:
                    max_age = int(match.group(1))
                    if max_age < 31536000:
                        vuln = Vulnerability(
                            name="Weak HSTS max-age",
                            description=f"HSTS max-age is {max_age}s (recommended minimum: 31536000s / 1 year)",
                            severity=Severity.LOW,
                            url=url,
                            parameter="Strict-Transport-Security",
                            payload=hsts,
                            evidence=f"max-age={max_age} < 31536000",
                            remediation="Set HSTS max-age to at least 31536000 seconds (1 year).",
                            cvss_score=2.5,
                            confidence=1.0,
                            module="headers"
                        )
                        async with self.results_lock:
                            self.vulnerabilities.append(vuln)
            if 'includesubdomains' not in hsts.lower():
                vuln = Vulnerability(
                    name="HSTS Missing includeSubDomains",
                    description="HSTS header does not include 'includeSubDomains' directive",
                    severity=Severity.LOW,
                    url=url,
                    parameter="Strict-Transport-Security",
                    payload=hsts,
                    evidence="includeSubDomains directive missing",
                    remediation="Add 'includeSubDomains' to HSTS header.",
                    cvss_score=2.5,
                    confidence=1.0,
                    module="headers"
                )
                async with self.results_lock:
                    self.vulnerabilities.append(vuln)

    async def _check_csp(self, headers: Dict[str, str], url: str) -> None:
        csp = headers.get('content-security-policy', '')
        if not csp:
            vuln = Vulnerability(
                name="Missing CSP Header",
                description="Content-Security-Policy header is missing. Site is vulnerable to XSS attacks.",
                severity=Severity.MEDIUM,
                url=url,
                parameter="Content-Security-Policy",
                payload="Missing",
                evidence="CSP header not present in response",
                remediation="Implement Content-Security-Policy header with appropriate directives.",
                cvss_score=5.0,
                confidence=1.0,
                module="headers"
            )
            async with self.results_lock:
                self.vulnerabilities.append(vuln)
        else:
            csp_lower = csp.lower()
            issues = []
            if "unsafe-inline" in csp_lower:
                issues.append("CSP allows 'unsafe-inline' which weakens XSS protection")
            if "unsafe-eval" in csp_lower:
                issues.append("CSP allows 'unsafe-eval' which enables eval() execution")
            if "*" in csp and "default-src" in csp_lower:
                issues.append("CSP default-src uses wildcard '*'")
            if "script-src" not in csp_lower and "default-src" not in csp_lower:
                issues.append("CSP does not restrict script sources")

            if issues:
                vuln = Vulnerability(
                    name=f"CSP Weakness",
                    description="; ".join(issues),
                    severity=Severity.LOW,
                    url=url,
                    parameter="Content-Security-Policy",
                    payload=csp[:200],
                    evidence=f"CSP issues: {len(issues)}",
                    remediation="Use strict CSP with nonces or hashes. Avoid unsafe-inline, unsafe-eval, and wildcards.",
                    cvss_score=3.5,
                    confidence=0.9,
                    module="headers"
                )
                async with self.results_lock:
                    self.vulnerabilities.append(vuln)

    async def _check_xframe(self, headers: Dict[str, str], url: str) -> None:
        xfo = headers.get('x-frame-options', '')
        if not xfo:
            vuln = Vulnerability(
                name="Missing X-Frame-Options Header",
                description="X-Frame-Options header is missing. Site is vulnerable to clickjacking attacks.",
                severity=Severity.MEDIUM,
                url=url,
                parameter="X-Frame-Options",
                payload="Missing",
                evidence="X-Frame-Options header not present",
                remediation="Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' header.",
                cvss_score=4.3,
                confidence=1.0,
                module="headers"
            )
            async with self.results_lock:
                self.vulnerabilities.append(vuln)

    async def _check_xxp(self, headers: Dict[str, str], url: str) -> None:
        xxp = headers.get('x-xss-protection', '')
        if not xxp:
            vuln = Vulnerability(
                name="Missing X-XSS-Protection Header",
                description="X-XSS-Protection header is missing",
                severity=Severity.LOW,
                url=url,
                parameter="X-XSS-Protection",
                payload="Missing",
                evidence="X-XSS-Protection header not present",
                remediation="Add 'X-XSS-Protection: 1; mode=block' header.",
                cvss_score=2.5,
                confidence=0.8,
                module="headers"
            )
            async with self.results_lock:
                self.vulnerabilities.append(vuln)

    async def _check_content_type(self, headers: Dict[str, str], url: str) -> None:
        xcto = headers.get('x-content-type-options', '')
        if not xcto:
            vuln = Vulnerability(
                name="Missing X-Content-Type-Options Header",
                description="X-Content-Type-Options header is missing. Site is vulnerable to MIME-type sniffing attacks.",
                severity=Severity.LOW,
                url=url,
                parameter="X-Content-Type-Options",
                payload="Missing",
                evidence="X-Content-Type-Options header not present",
                remediation="Add 'X-Content-Type-Options: nosniff' header.",
                cvss_score=2.5,
                confidence=1.0,
                module="headers"
            )
            async with self.results_lock:
                self.vulnerabilities.append(vuln)

    async def _check_referrer_policy(self, headers: Dict[str, str], url: str) -> None:
        rp = headers.get('referrer-policy', '')
        if not rp:
            vuln = Vulnerability(
                name="Missing Referrer-Policy Header",
                description="Referrer-Policy header is missing. Referrer information may leak.",
                severity=Severity.LOW,
                url=url,
                parameter="Referrer-Policy",
                payload="Missing",
                evidence="Referrer-Policy header not present",
                remediation="Add 'Referrer-Policy: strict-origin-when-cross-origin' or similar.",
                cvss_score=2.0,
                confidence=0.9,
                module="headers"
            )
            async with self.results_lock:
                self.vulnerabilities.append(vuln)

    async def _check_permissions_policy(self, headers: Dict[str, str], url: str) -> None:
        pp = headers.get('permissions-policy', '')
        if not pp:
            vuln = Vulnerability(
                name="Missing Permissions-Policy Header",
                description="Permissions-Policy header is missing. Browser features are uncontrolled.",
                severity=Severity.INFO,
                url=url,
                parameter="Permissions-Policy",
                payload="Missing",
                evidence="Permissions-Policy header not present",
                remediation="Add Permissions-Policy header to restrict browser features.",
                cvss_score=0.0,
                confidence=0.8,
                module="headers"
            )
            async with self.results_lock:
                self.vulnerabilities.append(vuln)

    async def _check_feature_policy(self, headers: Dict[str, str], url: str) -> None:
        fp = headers.get('feature-policy', '')
        if not fp and 'permissions-policy' not in headers:
            pass
