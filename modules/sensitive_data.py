"""
Sensitive Data Exposure Scanner
Author: ARIF
"""

import asyncio
import logging
from typing import List, Optional, Dict
from core.engine import Vulnerability, Severity
from core.requester import Requester
from core.parser import ResponseParser


class SensitiveScanner:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.requester = Requester(config)
        self.parser = ResponseParser(config)
        self.vulnerabilities = []
        self.results_lock = asyncio.Lock()

    async def scan(self, target: str) -> List[Vulnerability]:
        self.logger.info(f"Starting Sensitive Data scan on {target}")
        self.vulnerabilities = []
        try:
            response = await self.requester.get(target)
            if not response:
                return self.vulnerabilities
            html = await response.text()
            headers = {k: v for k, v in response.headers.items()}

            tasks = []
            tasks.append(self._scan_html_content(html, target))
            tasks.append(self._scan_headers(headers, target))
            tasks.append(self._scan_common_endpoints(target))
            tasks.append(self._scan_js_files(target, html))
            tasks.append(self._scan_comments(html, target))

            await asyncio.gather(*tasks)
        except Exception as e:
            self.logger.error(f"Sensitive Data scan error on {target}: {e}")
        return self.vulnerabilities

    async def _scan_html_content(self, html: str, url: str) -> None:
        sensitive = self.parser.find_sensitive_data(html)
        seen_types = set()
        for item in sensitive:
            if item["type"] not in seen_types:
                seen_types.add(item["type"])
                severity = Severity.CRITICAL if item["type"] in [
                    "API Key / Token", "AWS Access Key", "AWS Secret Key",
                    "Private Key", "OAuth Token", "GitHub Token",
                    "Stripe API Key", "Database URL"
                ] else Severity.MEDIUM

                vuln = Vulnerability(
                    name=f"Sensitive Data Exposure - {item['type']}",
                    description=f"Sensitive data ({item['type']}) exposed in web page content",
                    severity=severity,
                    url=url,
                    parameter="HTML Content",
                    payload=item["value"],
                    evidence=f"Pattern: {item['pattern']}",
                    remediation="Remove sensitive data from client-side code. Use environment variables. Implement proper secrets management.",
                    cvss_score=9.0 if severity == Severity.CRITICAL else 5.5,
                    confidence=0.85,
                    module="sensitive"
                )
                async with self.results_lock:
                    self.vulnerabilities.append(vuln)

    async def _scan_headers(self, headers: Dict, url: str) -> None:
        sensitive_headers = [
            ('x-powered-by', 'X-Powered-By header discloses server technology'),
            ('x-aspnet-version', 'ASP.NET version disclosed'),
            ('x-aspnetmvc-version', 'ASP.NET MVC version disclosed'),
            ('server', 'Server header discloses software version'),
            ('x-runtime', 'X-Runtime header discloses execution time'),
            ('x-version', 'Version information disclosed'),
            ('x-backend-server', 'Backend server information disclosed'),
            ('x-generator', 'CMS/Generator information disclosed'),
        ]
        for header, description in sensitive_headers:
            header_val = headers.get(header, headers.get(header.title(), ''))
            if header_val:
                vuln = Vulnerability(
                    name=f"Sensitive Data Exposure - {header} Header",
                    description=description,
                    severity=Severity.LOW,
                    url=url,
                    parameter=header,
                    payload=header_val,
                    evidence=f"Header: {header}: {header_val}",
                    remediation="Remove or obfuscate server version headers.",
                    cvss_score=2.5,
                    confidence=0.95,
                    module="sensitive"
                )
                async with self.results_lock:
                    self.vulnerabilities.append(vuln)

    async def _scan_common_endpoints(self, target: str) -> None:
        from urllib.parse import urljoin
        sensitive_endpoints = [
            "/.env", "/.git/config", "/.gitignore", "/.htaccess", "/config.php",
            "/config.json", "/config.yaml", "/config.yml", "/configuration.php",
            "/database.yml", "/db.php", "/backup.sql", "/dump.sql", "/dump.rdb",
            "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/clientaccesspolicy.xml",
            "/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old",
            "/web.config", "/app.config", "/application.properties",
            "/docker-compose.yml", "/Dockerfile", "/kubeconfig", "/.kube/config",
            "/composer.json", "/composer.lock", "/package.json", "/yarn.lock",
            "/npm-debug.log", "/debug.log", "/error.log", "/access.log",
            "/credentials", "/credentials.json", "/key.json", "/service-account.json",
            "/phpinfo.php", "/info.php", "/test.php", "/admin.php",
            "/api/swagger.json", "/api/docs", "/swagger-ui.html",
            "/.aws/credentials", "/.aws/config", "/.azure/credentials",
            "/.npmrc", "/.dockercfg", "/.docker/config.json",
            "/server-status", "/server-info", "/status", "/health",
            "/actuator", "/actuator/info", "/actuator/health",
            "/graphql", "/graphiql", "/voyager"
        ]

        for endpoint in sensitive_endpoints:
            try:
                url = urljoin(target, endpoint)
                response = await self.requester.get(url)
                if response and response.status == 200:
                    content = await response.text()
                    content_len = len(content)
                    if content_len > 20 and any(
                        kw in content.lower() for kw in [
                            "password", "secret", "key", "token", "api_key",
                            "database", "username", "localhost", "root",
                            "wp-config", "db_password", "DB_HOST",
                            "DB_PASSWORD", "AWS_ACCESS_KEY", "AZURE_",
                            "private_key", "-----BEGIN", "JWT",
                            "environ", "config", "application"
                        ]
                    ):
                        vuln = Vulnerability(
                            name=f"Sensitive Endpoint Exposed - {endpoint}",
                            description=f"Sensitive configuration endpoint exposed: {endpoint}",
                            severity=Severity.CRITICAL,
                            url=url,
                            parameter=endpoint,
                            payload="N/A",
                            evidence=f"Endpoint accessible, contains sensitive-looking data ({content_len} bytes)",
                            remediation=f"Restrict access to {endpoint}. Remove from production or add authentication.",
                            cvss_score=9.0,
                            confidence=0.9,
                            module="sensitive"
                        )
                        async with self.results_lock:
                            self.vulnerabilities.append(vuln)
            except Exception:
                pass

    async def _scan_js_files(self, target: str, html: str) -> None:
        from urllib.parse import urljoin
        import re
        js_urls = re.findall(r'(?:src|href)=["\']([^"\']+\.js[^"\']*)["\']', html)
        for js_url in js_urls[:10]:
            try:
                full_url = urljoin(target, js_url)
                response = await self.requester.get(full_url)
                if not response:
                    continue
                content = await response.text()
                sensitive = self.parser.find_sensitive_data(content)
                seen = set()
                for item in sensitive:
                    if item["type"] not in seen:
                        seen.add(item["type"])
                        vuln = Vulnerability(
                            name=f"Sensitive Data in JS File - {item['type']}",
                            description=f"Sensitive data found in JavaScript file: {js_url}",
                            severity=Severity.HIGH,
                            url=full_url,
                            parameter="JS File",
                            payload=item["value"],
                            evidence=f"Pattern: {item['type']}",
                            remediation="Remove sensitive data from client-side JS.",
                            cvss_score=7.5,
                            confidence=0.8,
                            module="sensitive"
                        )
                        async with self.results_lock:
                            self.vulnerabilities.append(vuln)
            except Exception:
                pass

    async def _scan_comments(self, html: str, url: str) -> None:
        comments = self.parser.extract_comments(html)
        for comment in comments:
            sensitive_keywords = [
                "TODO", "FIXME", "HACK", "XXX", "BUG", "password", "secret",
                "key", "token", "admin", "login", "credential", "username",
                "delete", "remove", "disable", "bypass", "backdoor",
                "developer", "test", "debug", "todo", "fixme"
            ]
            comment_lower = comment.lower()
            found = [kw for kw in sensitive_keywords if kw.lower() in comment_lower]
            if found:
                vuln = Vulnerability(
                    name="Sensitive Information in HTML Comments",
                    description=f"HTML comments contain potentially sensitive information. Keywords: {', '.join(found)}",
                    severity=Severity.LOW,
                    url=url,
                    parameter="HTML Comment",
                    payload=f"Comment: {comment[:100]}",
                    evidence=f"Found keywords: {', '.join(found)}",
                    remediation="Remove sensitive comments from production code.",
                    cvss_score=2.5,
                    confidence=0.8,
                    module="sensitive"
                )
                async with self.results_lock:
                    self.vulnerabilities.append(vuln)
