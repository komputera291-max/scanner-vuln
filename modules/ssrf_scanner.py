"""
SSRF Scanner — Server-Side Request Forgery
Author: ARIF
"""

import asyncio
import logging
import socket
from typing import List, Optional, Dict
from urllib.parse import urlparse, urlencode, parse_qs
from core.engine import Vulnerability, Severity
from core.requester import Requester


class SsrfScanner:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.requester = Requester(config)
        self.vulnerabilities = []
        self.results_lock = asyncio.Lock()

    async def scan(self, target: str) -> List[Vulnerability]:
        self.logger.info(f"Starting SSRF scan on {target}")
        self.vulnerabilities = []
        try:
            response = await self.requester.get(target)
            if not response:
                return self.vulnerabilities
            html = await response.text()
            forms = await self.requester.extract_forms(target, html)
            params = await self.requester.extract_parameters(target)

            tasks = []
            for param_name, param_value in params.items():
                tasks.append(self._test_ssrf(target, param_name, param_value))
            for form in forms:
                for input_data in form.get("inputs", []):
                    name = input_data.get("name", "")
                    if any(kw in name.lower() for kw in ["url", "link", "src", "href", "file", "path", "redirect", "page", "load", "include"]):
                        tasks.append(self._test_ssrf_post(form["action"], name))
            if tasks:
                await asyncio.gather(*tasks)
        except Exception as e:
            self.logger.error(f"SSRF scan error on {target}: {e}")
        return self.vulnerabilities

    async def _test_ssrf(self, url: str, param: str, value: str) -> None:
        test_urls = [
            "http://127.0.0.1:80",
            "http://127.0.0.1:8080",
            "http://127.0.0.1:443",
            "http://127.0.0.1:22",
            "http://127.0.0.1:3306",
            "http://127.0.0.1:6379",
            "http://127.0.0.1:27017",
            "http://localhost:80",
            "http://localhost:8080",
            "http://[::1]:80",
            "http://2130706433:80",
            "http://0177.0.0.1:80",
            "http://0x7f000001:80",
            "http://0:80",
            "http://10.0.0.1:80",
            "http://172.16.0.1:80",
            "http://192.168.1.1:80",
            "http://169.254.169.254:80",
            "http://metadata.google.internal",
            "http://100.100.100.200",
            "file:///etc/passwd",
            "file:///c:/windows/win.ini"
        ]

        for test_url in test_urls:
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                params[param] = [test_url]
                new_query = urlencode(params, doseq=True)
                test_full_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

                response = await self.requester.get(test_full_url, timeout=10)
                if response:
                    test_html = await response.text()
                    if self._detect_ssrf_response(test_html, test_url):
                        vuln = Vulnerability(
                            name="Server-Side Request Forgery (SSRF)",
                            description=f"SSRF vulnerability in parameter '{param}' - server makes requests to arbitrary URLs",
                            severity=Severity.HIGH,
                            url=test_full_url,
                            parameter=param,
                            payload=test_url,
                            evidence=f"Internal resource accessed via URL '{test_url}'",
                            remediation="Validate and whitelist allowed URLs. Block private IP ranges. Use URL parsing libraries to prevent protocol smuggling.",
                            cvss_score=8.6,
                            confidence=0.7,
                            module="ssrf"
                        )
                        async with self.results_lock:
                            self.vulnerabilities.append(vuln)
            except Exception as e:
                self.logger.debug(f"SSRF test error: {e}")

    async def _test_ssrf_post(self, url: str, param: str) -> None:
        test_urls = [
            "http://127.0.0.1:80",
            "http://localhost:80",
            "http://169.254.169.254",
        ]
        for test_url in test_urls:
            try:
                data = {param: test_url}
                response = await self.requester.post(url, data=data, timeout=10)
                if response and self._detect_ssrf_response(await response.text(), test_url):
                    vuln = Vulnerability(
                        name="SSRF (POST)",
                        description=f"SSRF in POST parameter '{param}'",
                        severity=Severity.HIGH,
                        url=url,
                        parameter=param,
                        payload=test_url,
                        evidence="Internal resource access detected",
                        remediation="Whitelist allowed URLs.",
                        cvss_score=8.6,
                        confidence=0.6,
                        module="ssrf"
                    )
                    async with self.results_lock:
                        self.vulnerabilities.append(vuln)
            except Exception as e:
                self.logger.debug(f"SSRF POST test error: {e}")

    def _detect_ssrf_response(self, html: str, requested_url: str) -> bool:
        indicators = [
            "root:", "/bin/bash", "/bin/sh",
            "Microsoft Windows", "Windows Registry Editor",
            "<?xml", "SYSTEM", "CurrentControlSet",
            "<HTML>", "<html>", "<BODY>",
            "uid=", "gid=",
            "HTTP/1.1", "HTTP/1.0",
            "<!DOCTYPE"
        ]
        for indicator in indicators:
            if indicator in html:
                return True
        if "file://" in requested_url and len(html) > 100:
            return True
        return False
