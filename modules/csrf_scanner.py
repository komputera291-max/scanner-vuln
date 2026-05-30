"""
CSRF Scanner — Cross-Site Request Forgery Token Check
Author: ARIF
"""

import asyncio
import logging
import re
from typing import List, Optional, Dict
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from core.engine import Vulnerability, Severity
from core.requester import Requester


class CsrfScanner:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.requester = Requester(config)
        self.vulnerabilities = []
        self.results_lock = asyncio.Lock()

    async def scan(self, target: str) -> List[Vulnerability]:
        self.logger.info(f"Starting CSRF scan on {target}")
        self.vulnerabilities = []
        try:
            response = await self.requester.get(target)
            if not response:
                return self.vulnerabilities
            html = await response.text()
            forms = await self.requester.extract_forms(target, html)

            tasks = []
            for form in forms:
                tasks.append(self._analyze_form_csrf(form, target))
            if tasks:
                await asyncio.gather(*tasks)
        except Exception as e:
            self.logger.error(f"CSRF scan error on {target}: {e}")
        return self.vulnerabilities

    async def _analyze_form_csrf(self, form: Dict, base_url: str) -> None:
        try:
            csrf_patterns = [
                r'csrf', r'token', r'__token', r'_token', r'csrf_token',
                r'csrfmiddlewaretoken', r'csrf-key', r'xsrf', r'xsrf-token',
                r'__csrf', r'csrf_name', r'csrfvalue', r'csrftoken',
                r'YII_CSRF_TOKEN', r'ci_csrf_token', r'csrf_test_name',
                r'csrf_hash', r'csrf_token_name', r'csrf-key',
                r'form_build_id', r'form_token', r'form_id',
                r'_csrf_token', r'X-CSRF', r'x-csrf-token'
            ]

            inputs = form.get("inputs", [])
            input_names = [inp.get("name", "").lower() for inp in inputs]
            method = form.get("method", "GET").upper()

            has_csrf = any(
                any(re.search(pattern, name) for pattern in csrf_patterns)
                for name in input_names
            )

            if not has_csrf and method == "POST" and len(inputs) > 0:
                non_submit = [
                    inp for inp in inputs
                    if inp.get("type") not in ["submit", "button", "image", "hidden"]
                ]
                if len(non_submit) > 0:
                    form_action = form.get("action", base_url)
                    vuln = Vulnerability(
                        name="Cross-Site Request Forgery (CSRF)",
                        description=f"Form at {form_action} lacks CSRF protection token",
                        severity=Severity.MEDIUM,
                        url=form_action,
                        parameter=f"Form fields: {[i['name'] for i in inputs[:5]]}",
                        payload="N/A",
                        evidence=f"Form method: {method}, Inputs: {len(inputs)}, CSRF Token: Missing",
                        remediation="Implement CSRF tokens in all state-changing forms. Use SameSite cookies. Consider double-submit cookie pattern.",
                        cvss_score=5.3,
                        confidence=0.8,
                        module="csrf"
                    )
                    async with self.results_lock:
                        self.vulnerabilities.append(vuln)
        except Exception as e:
            self.logger.debug(f"CSRF form analysis error: {e}")
