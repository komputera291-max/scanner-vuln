"""
SSL/TLS Certificate & Cipher Checker
Author: ARIF
"""

import asyncio
import logging
import ssl
import socket
import time
from typing import List, Optional, Dict, Tuple
from urllib.parse import urlparse
from datetime import datetime
from core.engine import Vulnerability, Severity
from core.requester import Requester


class SslScanner:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.requester = Requester(config)
        self.vulnerabilities = []
        self.results_lock = asyncio.Lock()

    async def scan(self, target: str) -> List[Vulnerability]:
        self.logger.info(f"Starting SSL/TLS scan on {target}")
        self.vulnerabilities = []

        try:
            parsed = urlparse(target)
            hostname = (parsed.hostname or parsed.netloc.split(':')[0]).split('@')[-1].strip('[]')
            port = parsed.port or 443

            cert_info = await self._get_certificate_info(hostname, port)
            if not cert_info:
                vuln = Vulnerability(
                    name="SSL/TLS Not Detected",
                    description=f"Could not establish SSL/TLS connection to {hostname}:{port}",
                    severity=Severity.HIGH,
                    url=target,
                    parameter="SSL/TLS",
                    payload="N/A",
                    evidence=f"No SSL/TLS connection to {hostname}:{port}",
                    remediation="Ensure server supports HTTPS with valid SSL/TLS certificate.",
                    cvss_score=7.0,
                    confidence=0.9,
                    module="ssl"
                )
                async with self.results_lock:
                    self.vulnerabilities.append(vuln)
                return self.vulnerabilities

            await self._analyze_certificate(cert_info, target)
            await self._check_weak_protocols(hostname, port, target)
            await self._check_redirect(target)

        except Exception as e:
            self.logger.error(f"SSL/TLS scan error on {target}: {e}")

        return self.vulnerabilities

    async def _get_certificate_info(self, hostname: str, port: int) -> Optional[Dict]:
        try:
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            result = await asyncio.get_event_loop().run_in_executor(
                None, self._connect_ssl, sock, hostname, port, context
            )
            sock.close()
            return result
        except Exception as e:
            self.logger.debug(f"Certificate fetch error: {e}")
            return None

    def _connect_ssl(self, sock, hostname, port, context):
        try:
            ssock = context.wrap_socket(sock, server_hostname=hostname)
            ssock.settimeout(10)
            ssock.connect((hostname, port))
            cert = ssock.getpeercert()
            cipher = ssock.cipher()
            version = ssock.version()
            ssock.close()
            return {
                "cert": cert,
                "cipher": cipher,
                "version": version
            }
        except Exception as e:
            raise e

    async def _analyze_certificate(self, cert_info: Dict, target: str) -> None:
        try:
            cert = cert_info.get("cert", {})
            if not cert:
                return

            not_after_str = cert.get("notAfter", "")
            not_before_str = cert.get("notBefore", "")

            if not_after_str:
                not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                now = datetime.utcnow()
                days_left = (not_after - now).days

                if days_left < 0:
                    vuln = Vulnerability(
                        name="SSL Certificate Expired",
                        description=f"SSL certificate expired {abs(days_left)} days ago",
                        severity=Severity.HIGH,
                        url=target,
                        parameter="SSL Certificate",
                        payload="N/A",
                        evidence=f"Certificate expired on {not_after_str}",
                        remediation="Renew SSL certificate immediately.",
                        cvss_score=7.5,
                        confidence=1.0,
                        module="ssl"
                    )
                    async with self.results_lock:
                        self.vulnerabilities.append(vuln)
                elif days_left < 30:
                    vuln = Vulnerability(
                        name="SSL Certificate Expiring Soon",
                        description=f"SSL certificate expires in {days_left} days",
                        severity=Severity.MEDIUM,
                        url=target,
                        parameter="SSL Certificate",
                        payload=f"{days_left} days remaining",
                        evidence=f"Certificate expires on {not_after_str} ({days_left} days)",
                        remediation="Renew SSL certificate before it expires.",
                        cvss_score=5.0,
                        confidence=1.0,
                        module="ssl"
                    )
                    async with self.results_lock:
                        self.vulnerabilities.append(vuln)

            subject = dict(cert.get("subject", []))
            common_name = ""
            for item in cert.get("subject", []):
                for key, value in item:
                    if key == "commonName":
                        common_name = value

            issuer = dict(cert.get("issuer", []))
            issuer_cn = ""
            for item in cert.get("issuer", []):
                for key, value in item:
                    if key == "commonName":
                        issuer_cn = value

            san = []
            for ext in cert.get("subjectAltName", []):
                san.append(ext[1])

            cipher = cert_info.get("cipher", ("", "", ""))
            cipher_name = cipher[0] if cipher else ""

            weak_ciphers = ["RC4", "DES", "3DES", "MD5", "SHA1", "EXPORT", "NULL"]
            for weak in weak_ciphers:
                if weak.lower() in cipher_name.lower():
                    vuln = Vulnerability(
                        name=f"Weak SSL Cipher - {cipher_name}",
                        description=f"Server uses weak cipher: {cipher_name}",
                        severity=Severity.HIGH,
                        url=target,
                        parameter="SSL Cipher",
                        payload=cipher_name,
                        evidence=f"Cipher: {cipher_name}",
                        remediation="Disable weak ciphers. Use only strong ciphers (TLS 1.2+ with AEAD).",
                        cvss_score=7.0,
                        confidence=0.9,
                        module="ssl"
                    )
                    async with self.results_lock:
                        self.vulnerabilities.append(vuln)

            version = cert_info.get("version", "")
            if "TLSv1" in version and "TLSv1.2" not in version and "TLSv1.3" not in version:
                vuln = Vulnerability(
                    name=f"Old TLS Version - {version}",
                    description=f"Server uses outdated TLS version: {version}",
                    severity=Severity.HIGH,
                    url=target,
                    parameter="TLS Version",
                    payload=version,
                    evidence=f"Negotiated: {version}",
                    remediation="Disable TLS 1.0 and TLS 1.1. Use TLS 1.2 or TLS 1.3 only.",
                    cvss_score=6.5,
                    confidence=0.95,
                    module="ssl"
                )
                async with self.results_lock:
                    self.vulnerabilities.append(vuln)

        except Exception as e:
            self.logger.debug(f"Certificate analysis error: {e}")

    async def _check_weak_protocols(self, hostname: str, port: int, target: str) -> None:
        weak_tls_versions = [
            ("TLSv1.0", ssl.PROTOCOL_TLSv1),
            ("TLSv1.1", ssl.PROTOCOL_TLSv1_1),
        ]
        try:
            for version_name, proto in weak_tls_versions:
                try:
                    context = ssl.SSLContext(proto)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    ssock = context.wrap_socket(sock, server_hostname=hostname)
                    ssock.connect((hostname, port))
                    ssock.close()
                    sock.close()

                    vuln = Vulnerability(
                        name=f"Weak TLS Protocol - {version_name}",
                        description=f"Server supports deprecated {version_name} protocol",
                        severity=Severity.MEDIUM,
                        url=target,
                        parameter="TLS Version",
                        payload=version_name,
                        evidence=f"{version_name} connection succeeded",
                        remediation=f"Disable {version_name} on server. Use TLS 1.2 or TLS 1.3.",
                        cvss_score=6.0,
                        confidence=0.95,
                        module="ssl"
                    )
                    async with self.results_lock:
                        self.vulnerabilities.append(vuln)

                except Exception:
                    pass
        except Exception as e:
            self.logger.debug(f"Weak protocol check error: {e}")

    async def _check_redirect(self, target: str) -> None:
        if target.startswith("http://"):
            https_url = target.replace("http://", "https://", 1)
            try:
                response = await self.requester.get(target, allow_redirects=False)
                if response:
                    location = response.headers.get('Location', '')
                    if not location or "https" not in location.lower():
                        vuln = Vulnerability(
                            name="Missing HTTPS Redirect",
                            description="HTTP site does not redirect to HTTPS",
                            severity=Severity.HIGH,
                            url=target,
                            parameter="HTTP Redirect",
                            payload="N/A",
                            evidence=f"HTTP request did not redirect to HTTPS. Status: {response.status}",
                            remediation="Implement 301 redirect from HTTP to HTTPS for all requests.",
                            cvss_score=6.5,
                            confidence=0.9,
                            module="ssl"
                        )
                        async with self.results_lock:
                            self.vulnerabilities.append(vuln)
            except Exception as e:
                self.logger.debug(f"Redirect check error: {e}")
