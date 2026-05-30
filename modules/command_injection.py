"""
Command Injection Scanner — OS Command Injection
Author: ARIF
"""

import asyncio
import logging
import re
import time
from typing import List, Optional, Dict
from urllib.parse import urlparse, urlencode, parse_qs
from core.engine import Vulnerability, Severity
from core.requester import Requester
from payloads.engine.generator import PayloadGenerator


class CmdiScanner:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.requester = Requester(config)
        self.payload_gen = PayloadGenerator(config)
        self.vulnerabilities = []
        self.results_lock = asyncio.Lock()

    async def scan(self, target: str) -> List[Vulnerability]:
        self.logger.info(f"Starting Command Injection scan on {target}")
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
                tasks.append(self._test_cmdi_get(target, param_name, param_value))
            for form in forms:
                for input_data in form.get("inputs", []):
                    if input_data.get("type") not in ["submit", "button", "image"]:
                        tasks.append(self._test_cmdi_post(form["action"], input_data["name"]))
            if tasks:
                await asyncio.gather(*tasks)
        except Exception as e:
            self.logger.error(f"Command Injection scan error on {target}: {e}")
        return self.vulnerabilities

    async def _test_cmdi_get(self, url: str, param: str, value: str) -> None:
        payloads = self.payload_gen.get_payloads("command", limit=80)
        base_html = ""
        base_resp = await self.requester.get(url)
        if base_resp:
            try:
                base_html = await base_resp.text()
            except Exception:
                pass

        for payload in payloads[:50]:
            try:
                test_url = self._inject_param(url, param, payload)
                start = time.time()
                response = await self.requester.get(test_url)
                elapsed = time.time() - start
                if not response:
                    continue
                test_html = await response.text()

                vuln = self._analyze_cmdi_response(
                    url, param, payload, test_html, base_html, elapsed
                )
                if vuln:
                    async with self.results_lock:
                        self.vulnerabilities.append(vuln)
            except Exception as e:
                self.logger.debug(f"CMDi test error: {e}")

    async def _test_cmdi_post(self, url: str, param: str) -> None:
        payloads = self.payload_gen.get_payloads("command", limit=30)
        for payload in payloads[:20]:
            try:
                data = {param: payload}
                start = time.time()
                response = await self.requester.post(url, data=data)
                elapsed = time.time() - start
                if not response:
                    continue
                test_html = await response.text()

                if self._check_os_command_injection(test_html):
                    vuln = Vulnerability(
                        name="Command Injection (POST)",
                        description=f"OS Command Injection in POST parameter '{param}'",
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=f"Command output detected in response (elapsed: {elapsed:.1f}s)",
                        remediation="Use proper input validation. Avoid passing user input directly to system commands. Use language-native APIs instead.",
                        cvss_score=9.8,
                        confidence=0.8,
                        module="cmdi"
                    )
                    async with self.results_lock:
                        self.vulnerabilities.append(vuln)
            except Exception as e:
                self.logger.debug(f"CMDi POST test error: {e}")

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        query_str = f"?{new_query}" if new_query else ""
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}{query_str}"

    def _analyze_cmdi_response(self, url: str, param: str, payload: str,
                                test_html: str, base_html: str,
                                elapsed: float) -> Optional[Vulnerability]:
        if self._check_os_command_injection(test_html):
            return Vulnerability(
                name="Command Injection",
                description=f"OS Command Injection in parameter '{param}'",
                severity=Severity.CRITICAL,
                url=url,
                parameter=param,
                payload=payload,
                evidence="Command execution detected in response",
                remediation="Use proper input validation and parameterized commands.",
                cvss_score=9.8,
                confidence=0.85,
                module="cmdi"
            )

        time_payloads = ["sleep 5", "ping -c 5 127.0.0.1", "timeout 5"]
        if any(tp in payload.lower() for tp in time_payloads):
            if elapsed >= 4.5:
                return Vulnerability(
                    name="Command Injection (Time-based)",
                    description=f"Time-based Command Injection in parameter '{param}'",
                    severity=Severity.HIGH,
                    url=url,
                    parameter=param,
                    payload=payload,
                    evidence=f"Response time: {elapsed:.1f}s (expected <1s)",
                    remediation="Sanitize input. Use safe APIs.",
                    cvss_score=8.0,
                    confidence=0.75,
                    module="cmdi"
                )

        if base_html and test_html:
            if len(test_html) > len(base_html) * 2 and len(test_html) > 1000:
                return Vulnerability(
                    name="Command Injection (Blind)",
                    description=f"Potential blind OS Command Injection in parameter '{param}'",
                    severity=Severity.HIGH,
                    url=url,
                    parameter=param,
                    payload=payload,
                    evidence=f"Response length changed: {len(base_html)} -> {len(test_html)}",
                    remediation="Sanitize user input.",
                    cvss_score=7.0,
                    confidence=0.5,
                    module="cmdi"
                )
        return None

    def _check_os_command_injection(self, html: str) -> bool:
        indicators = [
            r"UID\s+\w+\s+PID",
            r"root:x?:0:0:",
            r"Microsoft Windows",
            r"Linux \d+\.\d+\.\d+",
            r"total \d+\s+drwx",
            r"DIR\s+\w+[/\\]",
            r"Volume in drive",
            r"Directory of",
            r"(\d{2}:){2}\d{2}\s+(AM|PM)",
            r"uid=\d+\(\w+\)",
            r"gid=\d+\(\w+\)",
            r"groups=\d+\(\w+\)",
            r"\bwww\s+\d+\s+\d+\s+\w+\s+\d+\s+\w+\s+\d+",
            r"\/bin\/bash",
            r"\/usr\/bin",
            r"appdata",
            r"program files",
            r"system32"
        ]
        html_lower = html.lower()
        for pattern in indicators:
            if re.search(pattern, html, re.IGNORECASE):
                return True

        if "uid=" in html_lower or "gid=" in html_lower:
            return True
        if "total " in html_lower and ("drwx" in html_lower or "dr-" in html_lower):
            return True
        return False
