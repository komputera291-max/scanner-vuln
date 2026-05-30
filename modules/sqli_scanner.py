"""
SQL Injection Scanner — Error-based, Boolean, Time-based, Union
Author: ARIF
"""

import asyncio
import logging
import time
from typing import List, Optional, Dict
from urllib.parse import urlparse, urlencode, parse_qs
from core.engine import Vulnerability, Severity
from core.requester import Requester
from payloads.engine.generator import PayloadGenerator


class SqliScanner:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.requester = Requester(config)
        self.payload_gen = PayloadGenerator(config)
        self.vulnerabilities = []
        self.results_lock = asyncio.Lock()

    async def scan(self, target: str) -> List[Vulnerability]:
        self.logger.info(f"Starting SQLi scan on {target}")
        self.vulnerabilities = []

        try:
            html = None
            response = await self.requester.get(target)
            if response and response.status < 400:
                html = await response.text()
            else:
                self.logger.warning(f"Failed to access {target}")
                return self.vulnerabilities

            forms = await self.requester.extract_forms(target, html or "")
            params = await self.requester.extract_parameters(target)

            tasks = []

            for param_name, param_value in params.items():
                tasks.append(self._test_parameter_get(target, param_name, param_value))

            for form in forms:
                for input_data in form.get("inputs", []):
                    if input_data.get("type") not in ["submit", "button", "image", "hidden"]:
                        tasks.append(self._test_parameter_post(
                            form["action"], input_data["name"], form["method"]
                        ))

            if tasks:
                await asyncio.gather(*tasks)

        except Exception as e:
            self.logger.error(f"SQLi scan error on {target}: {e}")

        return self.vulnerabilities

    async def _test_parameter_get(self, url: str, param: str, value: str) -> None:
        payloads = self.payload_gen.get_payloads("sqli", limit=100)
        base_response = await self.requester.get(url)
        if not base_response:
            return
        try:
            base_html = await base_response.text()
        except Exception:
            base_html = ""

        for payload in payloads[:50]:
            try:
                test_url = self._inject_param(url, param, payload)
                response = await self.requester.get(test_url)
                if not response:
                    continue
                test_html = await response.text()

                vuln = self._analyze_sqli_response(
                    url, param, payload, base_html, test_html,
                    response.status, base_response.status if base_response else 200
                )
                if vuln:
                    async with self.results_lock:
                        self.vulnerabilities.append(vuln)
            except Exception as e:
                self.logger.debug(f"SQLi test error: {e}")

    async def _test_parameter_post(self, url: str, param: str, method: str) -> None:
        payloads = self.payload_gen.get_payloads("sqli", limit=50)
        for payload in payloads[:30]:
            try:
                data = {param: payload}
                response = await self.requester.post(url, data=data)
                if not response:
                    continue
                try:
                    test_html = await response.text()
                except Exception:
                    test_html = ""

                if self._check_sqli_in_response(test_html):
                    vuln = Vulnerability(
                        name="SQL Injection (POST)",
                        description=f"SQL Injection vulnerability detected in POST parameter '{param}'",
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=f"Status: {response.status}, Length: {len(test_html)}",
                        remediation="Use parameterized queries / prepared statements. Implement input validation and sanitization.",
                        cvss_score=9.8,
                        confidence=0.85,
                        module="sqli"
                    )
                    async with self.results_lock:
                        self.vulnerabilities.append(vuln)
            except Exception as e:
                self.logger.debug(f"SQLi POST test error: {e}")

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

    def _analyze_sqli_response(self, url: str, param: str, payload: str,
                                base_html: str, test_html: str,
                                test_status: int, base_status: int) -> Optional[Vulnerability]:
        from core.parser import ResponseParser
        parser = ResponseParser(self.config)

        if parser.has_sqli_error(test_html):
            evidence = self._extract_error_snippet(test_html)
            return Vulnerability(
                name="SQL Injection (Error-based)",
                description=f"Error-based SQL Injection in parameter '{param}'",
                severity=Severity.CRITICAL,
                url=url,
                parameter=param,
                payload=payload,
                evidence=evidence,
                remediation="Use parameterized queries / prepared statements.",
                cvss_score=9.8,
                confidence=0.95,
                module="sqli"
            )

        time_payloads = ["SLEEP(5)", "WAITFOR DELAY '0:0:5'", "pg_sleep(5)", "sleep(5)#"]
        if any(tp in payload.upper() for tp in time_payloads):
            response_time = getattr(test_html, '_response_time', 0)
            if response_time >= 4.5:
                return Vulnerability(
                    name="SQL Injection (Time-based)",
                    description=f"Time-based Blind SQL Injection in parameter '{param}'",
                    severity=Severity.HIGH,
                    url=url,
                    parameter=param,
                    payload=payload,
                    evidence=f"Response time: {response_time:.1f}s (expected <1s)",
                    remediation="Use parameterized queries. Implement query timeout limits.",
                    cvss_score=7.5,
                    confidence=0.80,
                    module="sqli"
                )

        if base_html and test_html:
            diff = parser.analyze_response_diff(base_html, test_html)
            if diff["similarity"] < 0.5 and diff["length_diff"] != 0:
                bool_payloads = ["' OR '1'='1", "1' OR '1'='1", "1' AND '1'='2"]
                if any(bp in payload.lower() for bp in bool_payloads):
                    return Vulnerability(
                        name="SQL Injection (Boolean-based)",
                        description=f"Boolean-based Blind SQL Injection in parameter '{param}'",
                        severity=Severity.HIGH,
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=f"Response similarity: {diff['similarity']:.2f}, Length diff: {diff['length_diff']}",
                        remediation="Use parameterized queries.",
                        cvss_score=7.5,
                        confidence=0.75,
                        module="sqli"
                    )

        return None

    def _check_sqli_in_response(self, html: str) -> bool:
        from core.parser import ResponseParser
        parser = ResponseParser(self.config)
        return parser.has_sqli_error(html)

    def _extract_error_snippet(self, html: str, max_len: int = 200) -> str:
        import re
        patterns = [
            r'(?:SQL syntax.*?MySQL|Warning.*?mysql_|MySQLSyntaxErrorException|PostgreSQL.*?ERROR)[^<]{0,200}',
            r'(?:Warning.*?pg_|Uncaught.*?mysqli_sql_exception|ORA-\d{5})[^<]{0,200}',
            r'you have an error in your sql[^<]{0,200}',
            r'(?:Microsoft.*?ODBC.*?SQL Server|Incorrect syntax near)[^<]{0,200}',
            r'(?:Unclosed quotation mark|PDOException.*?SQL)[^<]{0,200}'
        ]
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(0)[:max_len]
        error_keywords = ["sql", "sqlite", "mysql", "postgresql", "oracle", "odbc"]
        for kw in error_keywords:
            idx = html.lower().find(kw)
            if idx != -1:
                return html[max(0, idx - 20):idx + 150]
        return ""
