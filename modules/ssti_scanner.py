"""
SSTI Scanner — Server-Side Template Injection
Author: ARIF
"""

import asyncio
import logging
import re
from typing import List, Optional, Dict
from urllib.parse import urlparse, urlencode, parse_qs
from core.engine import Vulnerability, Severity
from core.requester import Requester


class SstiScanner:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.requester = Requester(config)
        self.vulnerabilities = []
        self.results_lock = asyncio.Lock()

    async def scan(self, target: str) -> List[Vulnerability]:
        self.logger.info(f"Starting SSTI scan on {target}")
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
                tasks.append(self._test_ssti(target, param_name))
            for form in forms:
                for input_data in form.get("inputs", []):
                    if input_data.get("type") in ["text", "textarea", "search"]:
                        tasks.append(self._test_ssti_post(form["action"], input_data["name"]))
            if tasks:
                await asyncio.gather(*tasks)
        except Exception as e:
            self.logger.error(f"SSTI scan error on {target}: {e}")
        return self.vulnerabilities

    async def _test_ssti(self, url: str, param: str) -> None:
        test_payloads = {
            "jinja2": ["{{7*7}}", "{{7*'7'}}", "{{config}}", "{{self.__class__}}"],
            "twig": ["{{7*7}}", "{{7*'7'}}", "{{_self.env}}"],
            "smarty": ["{$smarty.version}", "{7*7}", "{php}echo 49;{/php}"],
            "freemarker": ["${7*7}", "${7*7}", "${''.class.forName('java.lang.Runtime')}"],
            "velocity": ["#set($x=7*7)$x", "$x.getClass().forName('java.lang.Runtime')"],
            "mako": ["${7*7}", "${self.__class__}"],
            "jade": ["#{(7*7)}", "#{7*7}"],
            "handlebars": ["{{7*7}}", "{{constructor}}"],
            "pug": ["#{7*7}", "!=7*7"],
            "eruby": ["<%= 7*7 %>", "<%= system('id') %>"],
            "mustache": ["{{7*7}}", "{{#}}"],
            "jinjava": ["{{7*7}}", "{{7*'7'}}"],
            "blade": ["{{7*7}}", "{{7*'7'}}"],
            "go": ["{{.}}", "{{printf \"%d\" 7*7}}"]
        }

        for engine, payloads in test_payloads.items():
            for payload in payloads[:3]:
                try:
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query, keep_blank_values=True)
                    params[param] = [payload]
                    new_query = urlencode(params, doseq=True)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

                    response = await self.requester.get(test_url)
                    if not response:
                        continue
                    test_html = await response.text()

                    result = self._evaluate_ssti(test_html, payload, engine)
                    if result:
                        vuln = Vulnerability(
                            name=f"Server-Side Template Injection ({engine})",
                            description=f"SSTI vulnerability in parameter '{param}' - {engine} template engine detected",
                            severity=Severity.CRITICAL,
                            url=test_url,
                            parameter=param,
                            payload=payload,
                            evidence=result,
                            remediation="Do not allow user input in template expressions. Use sandboxed template engines. Input sanitization.",
                            cvss_score=9.8,
                            confidence=0.85 if engine else 0.5,
                            module="ssti"
                        )
                        async with self.results_lock:
                            self.vulnerabilities.append(vuln)
                except Exception as e:
                    self.logger.debug(f"SSTI test error: {e}")

    async def _test_ssti_post(self, url: str, param: str) -> None:
        basic_payloads = ["{{7*7}}", "${7*7}", "{7*7}"]
        for payload in basic_payloads:
            try:
                data = {param: payload}
                response = await self.requester.post(url, data=data)
                if not response:
                    continue
                test_html = await response.text()
                if "49" in test_html or "7*7" not in test_html:
                    vuln = Vulnerability(
                        name="Server-Side Template Injection (POST)",
                        description=f"SSTI vulnerability in POST parameter '{param}'",
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=f"Template expression evaluated: {payload} -> found in response",
                        remediation="Avoid user input in templates.",
                        cvss_score=9.8,
                        confidence=0.7,
                        module="ssti"
                    )
                    async with self.results_lock:
                        self.vulnerabilities.append(vuln)
            except Exception as e:
                self.logger.debug(f"SSTI POST test error: {e}")

    def _evaluate_ssti(self, html: str, payload: str, engine: str) -> Optional[str]:
        if "{{7*7}}" in payload or "${7*7}" in payload or "{7*7}" in payload:
            if "49" in html:
                return f"Template evaluated: payload produced '49' in response"
        if "{{7*'7'}}" in payload:
            if "7777777" in html:
                return f"Template evaluated: '7*\\'7\\'' produced '7777777'"
        if "{{config}}" in payload:
            if "ENV" in html or "SECRET" in html or "DEBUG" in html or "config" in html.lower():
                return "Configuration object leaked in response"
        if "{$smarty.version}" in payload:
            match = re.search(r'\d+\.\d+\.\d+', html)
            if match:
                return f"Smarty version: {match.group(0)}"
        if "/etc/passwd" in html or "root:" in html:
            return "File read via SSTI"
        if "Runtime" in html or "java.lang" in html.lower():
            return "Java reflection via SSTI"
        return None
