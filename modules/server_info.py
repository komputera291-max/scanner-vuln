"""
Server Information Disclosure Scanner
Author: ARIF
"""

import asyncio
import logging
import re
from typing import List, Optional, Dict
from urllib.parse import urljoin
from core.engine import Vulnerability, Severity
from core.requester import Requester


class ServerScanner:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.requester = Requester(config)
        self.vulnerabilities = []
        self.results_lock = asyncio.Lock()

    async def scan(self, target: str) -> List[Vulnerability]:
        self.logger.info(f"Starting Server Information scan on {target}")
        self.vulnerabilities = []
        try:
            response = await self.requester.get(target)
            if not response:
                return self.vulnerabilities

            headers = {}
            for k, v in response.headers.items():
                headers[k.lower()] = v

            await self._check_server_header(headers, target)
            await self._check_x_powered_by(headers, target)
            await self._check_error_pages(target)

        except Exception as e:
            self.logger.error(f"Server info scan error on {target}: {e}")
        return self.vulnerabilities

    async def _check_server_header(self, headers: Dict[str, str], url: str) -> None:
        server = headers.get('server', '')
        if server:
            vuln = Vulnerability(
                name="Server Information Disclosure",
                description=f"Server header discloses version information: '{server}'",
                severity=Severity.LOW,
                url=url,
                parameter="Server",
                payload=server,
                evidence=f"Server: {server}",
                remediation="Hide or obfuscate server version in headers. Use generic server names.",
                cvss_score=2.5,
                confidence=1.0,
                module="server"
            )
            async with self.results_lock:
                self.vulnerabilities.append(vuln)

    async def _check_x_powered_by(self, headers: Dict[str, str], url: str) -> None:
        for key in ['x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version']:
            val = headers.get(key, '')
            if val:
                vuln = Vulnerability(
                    name=f"Technology Disclosure - {key}",
                    description=f"Header '{key}' discloses: '{val}'",
                    severity=Severity.LOW,
                    url=url,
                    parameter=key,
                    payload=val,
                    evidence=f"{key}: {val}",
                    remediation="Remove or obfuscate technology-specific headers.",
                    cvss_score=2.0,
                    confidence=1.0,
                    module="server"
                )
                async with self.results_lock:
                    self.vulnerabilities.append(vuln)

    async def _check_error_pages(self, target: str) -> None:
        error_paths = [
            ("/nonexistent-page-test-12345", "404"),
            ("/../../../../../../../etc/passwd", "Path Traversal Error"),
            ("' OR '1'='1", "SQL Error"),
            ("<script>alert(1)</script>", "XSS in Error"),
            ("/admin", "Admin Panel"),
            ("/wp-admin", "WordPress Admin"),
            ("/.git", "Git Directory"),
            ("/.env", "Environment File"),
            ("/server-status", "Apache Status"),
            ("/phpinfo.php", "PHP Info"),
        ]

        for path, error_type in error_paths[:5]:
            try:
                url = urljoin(target, path)
                if ":" in path and not path.startswith("/"):
                    url = urljoin(target, "/") + path.lstrip("/")
                response = await self.requester.get(url)
                if not response:
                    continue
                html = await response.text()

                errors_found = []
                if "404" in error_type and response.status != 404:
                    if response.status == 200 or response.status == 500:
                        errors_found.append(f"Custom error page or information leak on {path}")

                php_info_indicators = ["PHP Version", "phpinfo()", "PHP Credits", "PHP License"]
                if any(ind in html for ind in php_info_indicators):
                    errors_found.append("PHP Info page exposed")

                git_indicators = ["[core]", "repositoryformatversion", "ref:"]
                if any(ind in html for ind in git_indicators):
                    errors_found.append("Git repository exposed (.git directory)")

                error_messages = re.findall(
                    r'(?:Warning|Error|Notice|Fatal|Exception):\s*[^<]{10,200}',
                    html, re.IGNORECASE
                )
                if error_messages:
                    errors_found.append(f"Error messages disclosed: {error_messages[0][:100]}")

                if errors_found:
                    vuln = Vulnerability(
                        name="Error Page Information Disclosure",
                        description="; ".join(errors_found),
                        severity=Severity.LOW,
                        url=url,
                        parameter=path,
                        payload="N/A",
                        evidence=f"Path: {path}, Status: {response.status}, Errors: {len(errors_found)}",
                        remediation="Use custom error pages. Disable detailed error messages in production.",
                        cvss_score=2.5,
                        confidence=0.7,
                        module="server"
                    )
                    async with self.results_lock:
                        self.vulnerabilities.append(vuln)

            except Exception as e:
                self.logger.debug(f"Error page check error: {e}")
