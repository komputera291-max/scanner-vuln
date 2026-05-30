"""
CORS Misconfiguration Scanner
Author: ARIF
"""

import asyncio
import logging
from typing import List, Optional, Dict
from urllib.parse import urlparse
from core.engine import Vulnerability, Severity
from core.requester import Requester


class CorsScanner:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.requester = Requester(config)
        self.vulnerabilities = []
        self.results_lock = asyncio.Lock()

    async def scan(self, target: str) -> List[Vulnerability]:
        self.logger.info(f"Starting CORS scan on {target}")
        self.vulnerabilities = []
        try:
            parsed = urlparse(target)
            origin_tests = [
                f"https://evil.com",
                f"https://{parsed.netloc}.evil.com",
                f"https://evil{parsed.netloc}",
                f"null",
                f"https://attacker.com",
                f"http://evil.com",
                f"https://evil.com:8080",
                f"https://{parsed.netloc}@evil.com",
            ]

            for origin in origin_tests:
                try:
                    headers = {"Origin": origin}
                    response = await self.requester.get(target, headers=headers)
                    if not response:
                        continue

                    resp_headers = {k.lower(): v for k, v in response.headers.items()}
                    acao = resp_headers.get('access-control-allow-origin', '')
                    acac = resp_headers.get('access-control-allow-credentials', '')
                    acam = resp_headers.get('access-control-allow-methods', '')
                    acah = resp_headers.get('access-control-allow-headers', '')

                    if acao:
                        if acao == '*':
                            vuln = Vulnerability(
                                name="CORS Misconfiguration - Wildcard Origin",
                                description="Access-Control-Allow-Origin set to '*' allowing any domain to access resources",
                                severity=Severity.MEDIUM,
                                url=target,
                                parameter="Origin header",
                                payload=f"Origin: {origin}",
                                evidence=f"ACAO: {acao}, ACAC: {acac}",
                                remediation="Restrict Access-Control-Allow-Origin to specific trusted domains. Avoid using wildcard with credentials.",
                                cvss_score=5.0,
                                confidence=0.95,
                                module="cors"
                            )
                            async with self.results_lock:
                                self.vulnerabilities.append(vuln)
                        elif origin == acao and 'null' in acao:
                            vuln = Vulnerability(
                                name="CORS Misconfiguration - Null Origin",
                                description="Access-Control-Allow-Origin reflects 'null' origin",
                                severity=Severity.MEDIUM,
                                url=target,
                                parameter="Origin header",
                                payload=f"Origin: null",
                                evidence=f"ACAO: null origin reflected",
                                remediation="Do not whitelist 'null' origin in CORS policies.",
                                cvss_score=5.0,
                                confidence=0.9,
                                module="cors"
                            )
                            async with self.results_lock:
                                self.vulnerabilities.append(vuln)
                        elif acao == origin or origin in acao:
                            if acac and acac.lower() == 'true':
                                vuln = Vulnerability(
                                    name="CORS Misconfiguration - Origin Reflection with Credentials",
                                    description=f"Access-Control-Allow-Origin reflects arbitrary origin with credentials enabled",
                                    severity=Severity.HIGH,
                                    url=target,
                                    parameter="Origin header",
                                    payload=f"Origin: {origin}",
                                    evidence=f"ACAO: {acao}, ACAC: {acac}",
                                    remediation="Use a whitelist of origins. Do not reflect arbitrary origins, especially with credentials.",
                                    cvss_score=7.0,
                                    confidence=0.9,
                                    module="cors"
                                )
                                async with self.results_lock:
                                    self.vulnerabilities.append(vuln)
                            else:
                                vuln = Vulnerability(
                                    name="CORS Misconfiguration - Origin Reflection",
                                    description="Access-Control-Allow-Origin reflects arbitrary origin",
                                    severity=Severity.MEDIUM,
                                    url=target,
                                    parameter="Origin header",
                                    payload=f"Origin: {origin}",
                                    evidence=f"Origin {origin} reflected in ACAO header",
                                    remediation="Whitelist specific origins instead of reflecting arbitrary origins.",
                                    cvss_score=5.0,
                                    confidence=0.85,
                                    module="cors"
                                )
                                async with self.results_lock:
                                    self.vulnerabilities.append(vuln)

                    options_headers = {"Origin": "https://evil.com", "Access-Control-Request-Method": "GET"}
                    preflight = await self.requester.options(target, headers=options_headers)
                    if preflight:
                        preflight_headers = {k.lower(): v for k, v in preflight.headers.items()}
                        if preflight_headers.get('access-control-allow-origin', '') == '*':
                            pass
                except Exception as e:
                    self.logger.debug(f"CORS test error for origin {origin}: {e}")

        except Exception as e:
            self.logger.error(f"CORS scan error on {target}: {e}")
        return self.vulnerabilities
