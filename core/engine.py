"""
CyberSecurity Scanner Core Engine
Author: ARIF
"""

import asyncio
import time
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import yaml
import os


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def score(self) -> float:
        scores = {
            "CRITICAL": 9.5,
            "HIGH": 7.5,
            "MEDIUM": 5.5,
            "LOW": 2.5,
            "INFO": 0.5
        }
        return scores[self.value]

    @property
    def color(self) -> str:
        colors = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "green"
        }
        return colors[self.value]


@dataclass
class Vulnerability:
    name: str
    description: str
    severity: Severity
    url: str
    parameter: str
    payload: str
    evidence: str
    remediation: str
    cvss_score: float
    confidence: float
    module: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "severity_score": self.severity.score,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cvss_score": self.cvss_score,
            "confidence": self.confidence,
            "module": self.module,
            "timestamp": self.timestamp
        }


@dataclass
class ScanResult:
    target: str
    start_time: float
    end_time: float = 0.0
    total_requests: int = 0
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    modules_ran: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    scan_id: str = ""

    @property
    def duration(self) -> float:
        if self.end_time:
            return self.end_time - self.start_time
        return time.time() - self.start_time

    @property
    def summary(self) -> Dict:
        vuln_count = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
            "total": len(self.vulnerabilities)
        }
        for v in self.vulnerabilities:
            vuln_count[v.severity.value] += 1
        return {
            "target": self.target,
            "scan_id": self.scan_id,
            "duration": self.duration,
            "total_requests": self.total_requests,
            "total_vulnerabilities": len(self.vulnerabilities),
            "vulnerabilities_by_severity": vuln_count,
            "modules_executed": len(self.modules_ran),
            "errors": len(self.errors)
        }

    def add_vulnerability(self, vuln: Vulnerability) -> None:
        self.vulnerabilities.append(vuln)

    def to_dict(self) -> Dict:
        return {
            "target": self.target,
            "scan_id": self.scan_id,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": self.duration,
            "total_requests": self.total_requests,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "modules_ran": self.modules_ran,
            "errors": self.errors,
            "summary": self.summary
        }


class ScanningEngine:
    def __init__(self, config_path: str = "config.yaml"):
        self.logger = logging.getLogger(__name__)
        self.config = self._load_config(config_path)
        self.modules = {}
        self.results = {}
        self._register_modules()

    def _load_config(self, path: str) -> Dict:
        default_config = {
            "requests": {"timeout": 30, "max_retries": 3},
            "threading": {"max_threads": 20},
            "scanning": {"depth": 3, "max_urls": 1000},
            "payload_generation": {"max_payloads_per_test": 500, "mutation_depth": 3},
            "reporting": {"output_dir": "output"},
            "logging": {"level": "INFO", "log_dir": "logs"}
        }
        try:
            if os.path.exists(path):
                with open(path, 'r') as f:
                    return {**default_config, **yaml.safe_load(f)}
        except Exception as e:
            self.logger.warning(f"Failed to load config: {e}")
        return default_config

    def _register_modules(self) -> None:
        module_names = [
            "sqli", "xss", "lfi", "cmdi", "ssrf", "ssti", "xxe",
            "csrf", "redirect", "upload", "idor", "auth", "sensitive",
            "cors", "headers", "cookie", "server", "ssl"
        ]
        for name in module_names:
            self.modules[name] = {"enabled": True, "instance": None}

    async def run_scan(self, target: str, modules: Optional[List[str]] = None,
                       scan_id: str = "") -> ScanResult:
        result = ScanResult(
            target=target,
            start_time=time.time(),
            scan_id=scan_id or f"scan_{int(time.time())}"
        )

        target = target.rstrip('/')
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"

        modules_to_run = modules or list(self.modules.keys())
        self.logger.info(f"Starting scan on {target} with {len(modules_to_run)} modules")

        semaphore = asyncio.Semaphore(self.config["threading"]["max_threads"])

        async def run_module(module_name: str) -> None:
            async with semaphore:
                try:
                    self.logger.info(f"Running module: {module_name}")
                    module_result = await self._execute_module(module_name, target)
                    if module_result:
                        for vuln in module_result:
                            result.add_vulnerability(vuln)
                    result.modules_ran.append(module_name)
                    result.total_requests += 1
                except Exception as e:
                    error_msg = f"Module {module_name} failed: {str(e)}"
                    self.logger.error(error_msg)
                    result.errors.append(error_msg)

        tasks = [run_module(m) for m in modules_to_run if m in self.modules]
        await asyncio.gather(*tasks)

        result.end_time = time.time()
        self.results[result.scan_id] = result
        self.logger.info(f"Scan completed. Found {len(result.vulnerabilities)} vulnerabilities")
        return result

    async def _execute_module(self, module_name: str, target: str) -> List[Vulnerability]:
        module_map = {
            "sqli": "modules.sqli_scanner",
            "xss": "modules.xss_scanner",
            "lfi": "modules.lfi_rfi_scanner",
            "cmdi": "modules.command_injection",
            "ssrf": "modules.ssrf_scanner",
            "ssti": "modules.ssti_scanner",
            "xxe": "modules.xxe_scanner",
            "csrf": "modules.csrf_scanner",
            "redirect": "modules.open_redirect",
            "upload": "modules.file_upload",
            "idor": "modules.idor_scanner",
            "auth": "modules.broken_auth",
            "sensitive": "modules.sensitive_data",
            "cors": "modules.cors_scanner",
            "headers": "modules.header_analyzer",
            "cookie": "modules.cookie_analyzer",
            "server": "modules.server_info",
            "ssl": "modules.ssl_tls_checker"
        }
        try:
            import importlib
            module_path = module_map.get(module_name)
            if not module_path:
                return []
            mod = importlib.import_module(module_path)
            scanner_class = getattr(mod, f"{module_name.title()}Scanner", None)
            if not scanner_class:
                return []
            scanner = scanner_class(self.config)
            return await scanner.scan(target)
        except Exception as e:
            self.logger.error(f"Error executing module {module_name}: {e}")
            return []

    def get_result(self, scan_id: str) -> Optional[ScanResult]:
        return self.results.get(scan_id)

    def get_all_results(self) -> Dict[str, ScanResult]:
        return self.results
