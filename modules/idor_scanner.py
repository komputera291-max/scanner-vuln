"""
IDOR Scanner — Insecure Direct Object Reference
Author: ARIF
"""

import asyncio
import logging
import re
from typing import List, Optional, Dict
from urllib.parse import urlparse, urlencode, parse_qs
from core.engine import Vulnerability, Severity
from core.requester import Requester


class IdorScanner:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.requester = Requester(config)
        self.vulnerabilities = []
        self.results_lock = asyncio.Lock()

    async def scan(self, target: str) -> List[Vulnerability]:
        self.logger.info(f"Starting IDOR scan on {target}")
        self.vulnerabilities = []
        try:
            response = await self.requester.get(target)
            if not response:
                return self.vulnerabilities
            html = await response.text()
            params = await self.requester.extract_parameters(target)

            tasks = []
            for param_name, param_value in params.items():
                if self._is_idor_candidate(param_name, param_value):
                    tasks.append(self._test_idor(target, param_name, param_value))
            if tasks:
                await asyncio.gather(*tasks)
        except Exception as e:
            self.logger.error(f"IDOR scan error on {target}: {e}")
        return self.vulnerabilities

    def _is_idor_candidate(self, name: str, value: str) -> bool:
        idor_patterns = r'(id|uid|pid|sid|gid|eid|tid|order|num|no|user|account|profile|document|file|attachment|page|post|product|category|item|record|ticket|invoice|transaction)'
        if re.search(idor_patterns, name, re.IGNORECASE):
            if value.isdigit() or re.match(r'^[a-f0-9]{8,}$', value, re.IGNORECASE):
                return True
        return False

    async def _test_idor(self, url: str, param: str, value: str) -> None:
        if value.isdigit():
            test_values = [str(int(value) + 1), str(int(value) - 1)]
        else:
            test_values = [value + "1", "test", "admin"]

        base_response = await self.requester.get(url)
        if not base_response:
            return
        base_html = await base_response.text()
        base_length = len(base_html)

        for test_val in test_values:
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                params[param] = [test_val]
                new_query = urlencode(params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

                response = await self.requester.get(test_url)
                if not response:
                    continue
                test_html = await response.text()

                if abs(len(test_html) - base_length) < 50:
                    continue

                if response.status == 200 and "403" not in test_html and "forbidden" not in test_html.lower() and "unauthorized" not in test_html.lower() and "access denied" not in test_html.lower():
                    vuln = Vulnerability(
                        name="Insecure Direct Object Reference (IDOR)",
                        description=f"IDOR vulnerability in parameter '{param}' - accessing different object ID returns data without proper authorization",
                        severity=Severity.HIGH,
                        url=test_url,
                        parameter=param,
                        payload=test_val,
                        evidence=f"Original value '{value}' changed to '{test_val}' returned 200 with content (len: {len(test_html)})",
                        remediation="Implement proper access control checks. Use indirect references. Verify user authorization for every object access.",
                        cvss_score=7.5,
                        confidence=0.7,
                        module="idor"
                    )
                    async with self.results_lock:
                        self.vulnerabilities.append(vuln)
            except Exception as e:
                self.logger.debug(f"IDOR test error: {e}")
