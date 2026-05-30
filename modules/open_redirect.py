"""
Open Redirect Scanner
Author: ARIF
"""

import asyncio
import logging
from typing import List, Optional, Dict
from urllib.parse import urlparse, urlencode, parse_qs, urljoin
from core.engine import Vulnerability, Severity
from core.requester import Requester


class RedirectScanner:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.requester = Requester(config)
        self.vulnerabilities = []
        self.results_lock = asyncio.Lock()

    async def scan(self, target: str) -> List[Vulnerability]:
        self.logger.info(f"Starting Open Redirect scan on {target}")
        self.vulnerabilities = []
        try:
            response = await self.requester.get(target)
            if not response:
                return self.vulnerabilities
            html = await response.text()
            params = await self.requester.extract_parameters(target)
            forms = await self.requester.extract_forms(target, html)

            tasks = []
            for param_name, param_value in params.items():
                tasks.append(self._test_redirect(target, param_name))
            for form in forms:
                for inp in form.get("inputs", []):
                    name = inp.get("name", "").lower()
                    if any(kw in name for kw in ["url", "link", "redirect", "return", "next", "goto", "target", "to", "page", "site", "path", "domain", "dest", "destination"]):
                        tasks.append(self._test_redirect_post(form["action"], inp["name"]))
            if tasks:
                await asyncio.gather(*tasks)
        except Exception as e:
            self.logger.error(f"Open Redirect scan error on {target}: {e}")
        return self.vulnerabilities

    async def _test_redirect(self, url: str, param: str) -> None:
        test_urls = [
            "https://evil.com",
            "http://evil.com",
            "//evil.com",
            "https://evil.com/test",
            "http://attacker.com",
            "https://google.com",
            "https://example.com@evil.com",
            "https://evil.com?@example.com",
            "https://evil.com#@example.com",
            "https://evil.com\\@example.com",
            "http://evil.com:80@example.com",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>"
        ]

        for redirect_url in test_urls:
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                params[param] = [redirect_url]
                new_query = urlencode(params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

                response = await self.requester.get(test_url, allow_redirects=False)
                if response:
                    location = response.headers.get('Location', response.headers.get('location', ''))
                    if location and self._is_external_redirect(location, url):
                        vuln = Vulnerability(
                            name="Open Redirect",
                            description=f"Open redirect vulnerability in parameter '{param}' - redirects to attacker-controlled URL",
                            severity=Severity.MEDIUM,
                            url=test_url,
                            parameter=param,
                            payload=redirect_url,
                            evidence=f"Redirect Location: {location}",
                            remediation="Validate and whitelist allowed redirect URLs. Use indirect references instead of direct URLs.",
                            cvss_score=4.3,
                            confidence=0.85 if "evil" in redirect_url else 0.6,
                            module="redirect"
                        )
                        async with self.results_lock:
                            self.vulnerabilities.append(vuln)
            except Exception as e:
                self.logger.debug(f"Redirect test error: {e}")

    async def _test_redirect_post(self, url: str, param: str) -> None:
        try:
            data = {param: "https://evil.com"}
            response = await self.requester.post(url, data=data, allow_redirects=False)
            if response:
                location = response.headers.get('Location', response.headers.get('location', ''))
                if "evil.com" in location:
                    vuln = Vulnerability(
                        name="Open Redirect (POST)",
                        description=f"Open redirect in POST parameter '{param}'",
                        severity=Severity.MEDIUM,
                        url=url,
                        parameter=param,
                        payload="https://evil.com",
                        evidence=f"Redirect: {location}",
                        remediation="Validate redirect URLs.",
                        cvss_score=4.3,
                        confidence=0.7,
                        module="redirect"
                    )
                    async with self.results_lock:
                        self.vulnerabilities.append(vuln)
        except Exception as e:
            self.logger.debug(f"Redirect POST test error: {e}")

    def _is_external_redirect(self, location: str, original_url: str) -> bool:
        parsed_orig = urlparse(original_url)
        parsed_loc = urlparse(location)
        if not parsed_loc.netloc:
            return False
        if parsed_loc.netloc == parsed_orig.netloc:
            return False
        if parsed_loc.netloc.replace("www.", "") == parsed_orig.netloc.replace("www.", ""):
            return False
        return True
