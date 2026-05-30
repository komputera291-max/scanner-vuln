"""
XSS Scanner — Reflected, Stored, DOM-based
Author: ARIF
"""

import asyncio
import logging
import re
from typing import List, Optional, Dict
from urllib.parse import urlparse, urlencode, parse_qs, urljoin
from bs4 import BeautifulSoup
from core.engine import Vulnerability, Severity
from core.requester import Requester
from payloads.engine.generator import PayloadGenerator


class XssScanner:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.requester = Requester(config)
        self.payload_gen = PayloadGenerator(config)
        self.vulnerabilities = []
        self.results_lock = asyncio.Lock()

    async def scan(self, target: str) -> List[Vulnerability]:
        self.logger.info(f"Starting XSS scan on {target}")
        self.vulnerabilities = []

        try:
            response = await self.requester.get(target)
            if not response or response.status >= 400:
                return self.vulnerabilities
            html = await response.text()
            forms = await self.requester.extract_forms(target, html)
            params = await self.requester.extract_parameters(target)

            tasks = []

            for param_name, param_value in params.items():
                tasks.append(self._test_reflected_get(target, param_name, param_value))

            for form in forms:
                for input_data in form.get("inputs", []):
                    if input_data.get("type") not in ["submit", "button", "image", "hidden"]:
                        tasks.append(self._test_reflected_post(
                            form["action"], input_data["name"]
                        ))

            tasks.append(self._test_stored_xss(target, forms))
            tasks.append(self._test_dom_xss(target, html))

            if tasks:
                await asyncio.gather(*tasks)

        except Exception as e:
            self.logger.error(f"XSS scan error on {target}: {e}")

        return self.vulnerabilities

    async def _test_reflected_get(self, url: str, param: str, value: str) -> None:
        payloads = self.payload_gen.get_payloads("xss", limit=150)
        base_response = await self.requester.get(url)
        if not base_response:
            return
        try:
            base_html = await base_response.text()
        except Exception:
            base_html = ""

        for payload in payloads[:80]:
            try:
                test_url = self._inject_param(url, param, payload)
                response = await self.requester.get(test_url)
                if not response:
                    continue
                test_html = await response.text()

                if self._check_xss_reflected(test_html, payload):
                    confidence = self._calculate_confidence(test_html, payload)
                    vuln = Vulnerability(
                        name="Cross-Site Scripting (XSS) - Reflected",
                        description=f"Reflected XSS vulnerability in parameter '{param}'",
                        severity=Severity.HIGH if confidence > 0.8 else Severity.MEDIUM,
                        url=test_url,
                        parameter=param,
                        payload=payload,
                        evidence=f"Payload reflected in response. Confidence: {confidence:.0%}",
                        remediation="Implement proper output encoding and Content Security Policy (CSP). Validate and sanitize all user input.",
                        cvss_score=6.1 if confidence > 0.8 else 4.3,
                        confidence=confidence,
                        module="xss"
                    )
                    async with self.results_lock:
                        self.vulnerabilities.append(vuln)
            except Exception as e:
                self.logger.debug(f"XSS GET test error: {e}")

    async def _test_reflected_post(self, url: str, param: str) -> None:
        payloads = self.payload_gen.get_payloads("xss", limit=50)
        for payload in payloads[:30]:
            try:
                data = {param: payload}
                response = await self.requester.post(url, data=data)
                if not response:
                    continue
                test_html = await response.text()

                if self._check_xss_reflected(test_html, payload):
                    vuln = Vulnerability(
                        name="Cross-Site Scripting (XSS) - Reflected (POST)",
                        description=f"Reflected XSS vulnerability in POST parameter '{param}'",
                        severity=Severity.HIGH,
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence="Payload reflected in POST response",
                        remediation="Implement output encoding and CSP.",
                        cvss_score=6.1,
                        confidence=0.8,
                        module="xss"
                    )
                    async with self.results_lock:
                        self.vulnerabilities.append(vuln)
            except Exception as e:
                self.logger.debug(f"XSS POST test error: {e}")

    async def _test_stored_xss(self, url: str, forms: List[Dict]) -> None:
        for form in forms[:5]:
            try:
                payload = "<script>alert('XSS_TEST_12345')</script>"
                form_data = {}
                for inp in form.get("inputs", []):
                    if inp.get("type") in ["text", "textarea", "search", "email", "url"]:
                        form_data[inp["name"]] = payload
                    elif inp.get("value"):
                        form_data[inp["name"]] = inp["value"]

                if form_data:
                    response = await self.requester.post(
                        form["action"], data=form_data
                    )
                    if response:
                        await asyncio.sleep(1)
                        check_response = await self.requester.get(url)
                        if check_response:
                            check_html = await check_response.text()
                            if "XSS_TEST_12345" in check_html or "alert('XSS" in check_html:
                                vuln = Vulnerability(
                                    name="Cross-Site Scripting (XSS) - Stored",
                                    description="Stored XSS vulnerability detected - payload persists on server",
                                    severity=Severity.CRITICAL,
                                    url=url,
                                    parameter=",".join(form_data.keys()),
                                    payload=payload,
                                    evidence="Payload persists across requests",
                                    remediation="Implement output encoding on output. Validate input server-side. Use CSP headers.",
                                    cvss_score=8.6,
                                    confidence=0.9,
                                    module="xss"
                                )
                                async with self.results_lock:
                                    self.vulnerabilities.append(vuln)
            except Exception as e:
                self.logger.debug(f"Stored XSS test error: {e}")

    async def _test_dom_xss(self, url: str, html: str) -> None:
        dom_sinks = [
            r'document\.write\s*\(',
            r'innerHTML\s*=',
            r'outerHTML\s*=',
            r'eval\s*\(',
            r'setTimeout\s*\(',
            r'setInterval\s*\(',
            r'location\s*=',
            r'location\.href\s*=',
            r'location\.replace\s*\(',
            r'location\.assign\s*\(',
            r'\.html\s*\(',
            r'\.append\s*\(',
            r'\.prepend\s*\(',
            r'\.after\s*\(',
            r'\.before\s*\(',
            r'\.replaceWith\s*\(',
            r'\.insertAdjacentHTML\s*\(',
            r'\$\(.*\)\.html\s*\(',
            r'\.write\s*\(',
            r'\.writeln\s*\('
        ]

        found_sinks = []
        for pattern in dom_sinks:
            matches = re.findall(pattern, html, re.IGNORECASE)
            if matches:
                found_sinks.extend(matches)

        if found_sinks:
            vuln = Vulnerability(
                name="Cross-Site Scripting (XSS) - DOM-based (Potential)",
                description=f"Potential DOM-based XSS - unsafe JavaScript sinks detected: {', '.join(found_sinks[:3])}",
                severity=Severity.MEDIUM,
                url=url,
                parameter="N/A (DOM-based)",
                payload="N/A",
                evidence=f"Detected DOM sinks: {', '.join(found_sinks[:5])}",
                remediation="Avoid using innerHTML, document.write, eval with user input. Use textContent or safe DOM APIs. Implement CSP.",
                cvss_score=4.3,
                confidence=0.5,
                module="xss"
            )
            async with self.results_lock:
                self.vulnerabilities.append(vuln)

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        query_str = f"?{new_query}" if new_query else ""
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}{query_str}"

    def _check_xss_reflected(self, html: str, payload: str) -> bool:
        if not payload or not html:
            return False
        check_payload = payload
        check_payload = check_payload.replace('+', ' ').replace('%3C', '<').replace('%3E', '>')
        check_payload = check_payload.replace('%22', '"').replace('%27', "'")
        check_payload = check_payload.replace('&lt;', '<').replace('&gt;', '>')
        check_payload = check_payload.replace('&quot;', '"').replace('&#x27;', "'")
        check_payload = check_payload.replace('&#60;', '<').replace('&#62;', '>')
        check_payload = check_payload.replace('&#34;', '"').replace('&#39;', "'")
        check_payload = re.sub(r'&#x[0-9a-fA-F]{2};', lambda m: chr(int(m.group(0)[3:5], 16)), check_payload)

        if check_payload in html:
            return True
        core_patterns = [
            r'<script[^>]*>.*?</script>',
            r'<img[^>]*onerror\s*=',
            r'<svg[^>]*onload\s*=',
            r'<body[^>]*onload\s*=',
            r'<input[^>]*onfocus\s*=',
            r'onmouseover\s*=',
            r'onclick\s*=',
            r'javascript\s*:\s*alert',
            r'<[^>]*\s*=?\s*["\']?\s*javascript:',
            r'fromCharCode\(',
            r'eval\s*\(\s*\\x',
            r'&#x[0-9a-fA-F]{2,4};'
        ]
        for pattern in core_patterns:
            if re.search(pattern, html, re.IGNORECASE):
                return True
        if len(set(html.split()) & set(payload.split())) >= 2:
            return True
        return False

    def _calculate_confidence(self, html: str, payload: str) -> float:
        confidence = 0.5
        if payload in html:
            confidence += 0.4
        check_tags = ["<script>", "<img", "<svg", "<body", "<input", "<iframe", "<div"]
        for tag in check_tags:
            if tag in payload and tag in html:
                confidence += 0.05
        event_handlers = ["onerror", "onload", "onclick", "onfocus", "onmouseover"]
        for handler in event_handlers:
            if handler in payload and handler in html.lower():
                confidence += 0.05
        if "alert(" in payload and ("alert(" in html or "alert(" in html.lower()):
            confidence += 0.1
        return min(confidence, 1.0)
