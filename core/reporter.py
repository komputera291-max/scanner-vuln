"""
Report Generator — HTML, JSON, TXT output
Author: ARIF
"""

import os
import re
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse
from core.engine import ScanResult, Severity


class ReportGenerator:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.output_dir = config.get("reporting", {}).get("output_dir", "output")

    def _get_next_scan_dir(self, target: str) -> str:
        domain = urlparse(target).hostname or target.split('/')[0]
        os.makedirs(self.output_dir, exist_ok=True)
        base_name = f"vuln {domain}"
        folder = os.path.join(self.output_dir, base_name)
        if not os.path.exists(folder):
            return folder
        n = 2
        while os.path.exists(f"{folder} {n}"):
            n += 1
        return f"{folder} {n}"

    def generate_all(self, result: ScanResult) -> Dict[str, str]:
        paths = {}
        scan_dir = self._get_next_scan_dir(result.target)
        os.makedirs(scan_dir, exist_ok=True)
        os.makedirs(os.path.join(scan_dir, "raw_requests"), exist_ok=True)
        os.makedirs(os.path.join(scan_dir, "logs"), exist_ok=True)

        formats = self.config.get("reporting", {}).get("formats", ["html", "json", "txt"])
        for fmt in formats:
            try:
                if fmt == "html":
                    path = self._generate_html(result, scan_dir)
                elif fmt == "json":
                    path = self._generate_json(result, scan_dir)
                elif fmt == "txt":
                    path = self._generate_txt(result, scan_dir)
                else:
                    continue
                paths[fmt] = path
            except Exception as e:
                self.logger.error(f"Failed to generate {fmt} report: {e}")

        latest_link = os.path.join(self.output_dir, "latest")
        try:
            if os.path.exists(latest_link):
                os.unlink(latest_link)
            os.symlink(os.path.basename(scan_dir), latest_link)
        except Exception:
            pass

        self.logger.info(f"Scan results saved to: {scan_dir}")

        return paths

    def _generate_html(self, result: ScanResult, scan_dir: str) -> str:
        filepath = os.path.join(scan_dir, "summary_report.html")
        summary = result.summary
        vulns_by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
        for v in result.vulnerabilities:
            vulns_by_severity[v.severity.value].append(v)

        def vuln_impact(name: str, module: str) -> str:
            name_l = name.lower()
            mod_l = module.lower()
            if "sqli" in mod_l or "sql injection" in name_l or "sql" in name_l:
                return "Attacker can extract, modify, or delete entire database contents, bypass authentication, execute remote commands, and gain full server access."
            if "xss" in mod_l or "cross site" in name_l or "script" in name_l:
                return "Attacker can hijack victim sessions, steal cookies and credentials, deface websites, redirect users to phishing pages, or deliver malware."
            if "lfi" in mod_l or "local file" in name_l or "rfi" in mod_l or "remote file" in name_l:
                return "Attacker can read sensitive server files (/etc/passwd, config files), execute arbitrary code, and gain full remote access to the server."
            if "cmdi" in mod_l or "command injection" in name_l or "cmd" in name_l:
                return "Attacker can execute arbitrary system commands on the server, leading to complete server compromise, data theft, and lateral movement."
            if "ssrf" in name_l:
                return "Attacker can probe internal networks, access cloud metadata services, read local files, and pivot to attack internal systems."
            if "ssti" in name_l or "template" in name_l:
                return "Attacker can execute arbitrary code on the server, read sensitive data, and achieve Remote Code Execution (RCE)."
            if "xxe" in name_l:
                return "Attacker can read arbitrary files on the server, perform SSRF attacks, cause denial of service, and potentially execute code."
            if "csrf" in name_l or "cross-site request" in name_l:
                return "Attacker can force authenticated users to perform unwanted actions (password change, fund transfer, data modification) without their knowledge."
            if "redirect" in name_l or "open redirect" in name_l:
                return "Attacker can redirect users to phishing sites, steal credentials, bypass URL validation, and spread malware."
            if "upload" in name_l or "file upload" in name_l:
                return "Attacker can upload malicious files (web shells, malware) leading to Remote Code Execution and full server compromise."
            if "idor" in name_l or "insecure direct" in name_l:
                return "Attacker can access, modify, or delete other users' private data by manipulating object references."
            if "auth" in mod_l or "authentication" in name_l or "login" in name_l:
                return "Attacker can bypass login mechanisms, brute-force credentials, perform session hijacking, and gain unauthorized access."
            if "sensitive" in mod_l or "sensitive data" in name_l or "exposure" in name_l:
                return "Sensitive information (credentials, tokens, personal data) exposed, enabling further attacks and data breaches."
            if "cors" in mod_l:
                return "Attacker can make cross-origin requests from malicious sites, potentially accessing sensitive API responses and user data."
            if "header" in mod_l or "security header" in name_l:
                return "Missing security headers expose users to clickjacking, MIME-type sniffing, and other client-side attacks."
            if "cookie" in mod_l or "cookie security" in name_l:
                return "Insecure cookies can be stolen via XSS, intercepted over HTTP, or manipulated, leading to session hijacking."
            if "ssl" in mod_l or "tls" in name_l or "certificate" in name_l:
                return "Weak SSL/TLS configuration allows man-in-the-middle attacks, data interception, and credential theft."
            if "server" in mod_l or "server info" in name_l or "disclosure" in name_l:
                return "Server information disclosure aids attackers in crafting targeted exploits by revealing software versions and configurations."
            return "This vulnerability can be exploited to compromise the confidentiality, integrity, or availability of the application and its data."

        html_parts = []
        html_parts.append('<!DOCTYPE html><html lang="en"><head>')
        html_parts.append('<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">')
        html_parts.append(f'<title>Security Scan Report - {result.target}</title>')
        html_parts.append("""
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Inter', 'Segoe UI', Arial, sans-serif; background: #000; color: #e0e0e0; padding: 24px; }
.container { max-width: 1280px; margin: 0 auto; }

/* Header */
.header { background: #0a0a0a; border: 1px solid #1a1a1a; border-radius: 16px; padding: 36px 32px; margin-bottom: 28px; }
.header h1 { color: #ffffff; font-size: 30px; font-weight: 700; letter-spacing: -0.5px; margin-bottom: 6px; }
.header .sub { color: #666; font-size: 13px; margin-bottom: 8px; }
.header .badge { display: inline-block; background: #111; border: 1px solid #222; border-radius: 6px; padding: 4px 12px; font-size: 12px; color: #888; margin-right: 8px; margin-top: 8px; }
.header .badge span { color: #fff; }

/* Summary Grid */
.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; margin-bottom: 32px; }
.summary-card { background: #0a0a0a; border: 1px solid #1a1a1a; border-radius: 12px; padding: 24px; text-align: center; transition: border-color .2s; }
.summary-card:hover { border-color: #333; }
.summary-card .num { font-size: 38px; font-weight: 800; margin-bottom: 4px; letter-spacing: -1px; }
.summary-card .lbl { color: #555; font-size: 11px; text-transform: uppercase; letter-spacing: 1.5px; font-weight: 600; }
.sc-critical .num { color: #ff002b; }
.sc-high .num { color: #ff4d00; }
.sc-medium .num { color: #ffaa00; }
.sc-low .num { color: #00bfff; }
.sc-info .num { color: #00ff88; }
.sc-total .num { color: #ffffff; }

/* Severity Sections */
.severity-section { margin-bottom: 28px; }
.severity-header { font-size: 18px; font-weight: 700; padding: 14px 20px; border-radius: 10px; margin-bottom: 12px; letter-spacing: -0.3px; display: flex; align-items: center; gap: 10px; }
.severity-header .count { background: rgba(255,255,255,0.05); border-radius: 20px; padding: 2px 12px; font-size: 13px; font-weight: 600; }
.sh-critical { background: #1a0508; color: #ff002b; border-left: 3px solid #ff002b; }
.sh-high { background: #1a0a05; color: #ff4d00; border-left: 3px solid #ff4d00; }
.sh-medium { background: #1a1200; color: #ffaa00; border-left: 3px solid #ffaa00; }
.sh-low { background: #000a1a; color: #00bfff; border-left: 3px solid #00bfff; }
.sh-info { background: #001a0a; color: #00ff88; border-left: 3px solid #00ff88; }

/* Vuln Cards */
.vuln-card { background: #080808; border: 1px solid #161616; border-radius: 12px; padding: 22px; margin-bottom: 10px; }
.vuln-card h3 { color: #ffffff; font-size: 16px; font-weight: 600; margin-bottom: 8px; letter-spacing: -0.2px; }
.vuln-card .desc { color: #888; font-size: 13px; margin-bottom: 14px; line-height: 1.5; }
.vuln-card .meta { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 12px; }
.vuln-card .mi { font-size: 12px; color: #999; }
.vuln-card .mi strong { color: #555; font-weight: 500; }
.vuln-card .mi code { background: #111; color: #aaa; padding: 1px 6px; border-radius: 3px; font-size: 11px; }
.vuln-card .payload-box { background: #0d0000; border: 1px solid #2a0000; border-radius: 8px; padding: 14px; margin: 10px 0; font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 13px; line-height: 1.7; overflow-x: auto; color: #ff6b6b; }
.vuln-card .payload-box::before { content: "Payload"; display: block; font-family: 'Inter', 'Segoe UI', Arial, sans-serif; font-size: 11px; font-weight: 600; color: #882222; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px; }
.vuln-card .impact-box { background: #000d08; border: 1px solid #002018; border-radius: 8px; padding: 14px; margin: 10px 0; font-size: 13px; line-height: 1.6; color: #88ddbb; }
.vuln-card .impact-box::before { content: "Impact"; display: block; font-family: 'Inter', 'Segoe UI', Arial, sans-serif; font-size: 11px; font-weight: 600; color: #226655; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 4px; }
.vuln-card .evidence { background: #050505; border: 1px solid #151515; border-radius: 6px; padding: 12px; font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 12px; line-height: 1.6; overflow-x: auto; margin-top: 10px; color: #bbb; }
.vuln-card .remediation { background: #001005; border: 1px solid #002010; border-radius: 6px; padding: 12px; margin-top: 10px; color: #00cc77; font-size: 13px; line-height: 1.5; }
.vuln-card .remediation::before { content: "Remediation: "; font-weight: 600; }

/* None found */
.none-found { color: #444; font-style: italic; padding: 28px; text-align: center; font-size: 14px; background: #080808; border: 1px dashed #1a1a1a; border-radius: 10px; }

/* Footer */
.footer { text-align: center; color: #333; font-size: 12px; margin-top: 48px; padding: 24px; border-top: 1px solid #111; }

/* Responsive */
@media (max-width: 640px) {
  body { padding: 12px; }
  .vuln-card .meta { grid-template-columns: 1fr; }
  .summary-grid { grid-template-columns: 1fr 1fr; }
}
</style></head><body>
<div class="container">""")

        html_parts.append(f'<div class="header">')
        html_parts.append(f'<h1>Security Scan Report</h1>')
        html_parts.append(f'<div class="sub">Target: {result.target} &middot; Scan ID: {result.scan_id}</div>')
        html_parts.append(f'<div class="sub">Date: {datetime.fromtimestamp(result.start_time).strftime("%Y-%m-%d %H:%M:%S")} &middot; Duration: {result.duration:.1f}s &middot; Requests: {result.total_requests}</div>')
        html_parts.append(f'<div class="badge">Modules: <span>{len(result.modules_ran)}</span></div>')
        html_parts.append(f'<div class="badge">Vulnerabilities: <span>{len(result.vulnerabilities)}</span></div>')
        html_parts.append('</div>')

        html_parts.append('<div class="summary-grid">')
        html_parts.append(f'<div class="summary-card sc-total"><div class="num">{len(result.vulnerabilities)}</div><div class="lbl">Total</div></div>')
        html_parts.append(f'<div class="summary-card sc-critical"><div class="num">{summary["vulnerabilities_by_severity"]["CRITICAL"]}</div><div class="lbl">Critical</div></div>')
        html_parts.append(f'<div class="summary-card sc-high"><div class="num">{summary["vulnerabilities_by_severity"]["HIGH"]}</div><div class="lbl">High</div></div>')
        html_parts.append(f'<div class="summary-card sc-medium"><div class="num">{summary["vulnerabilities_by_severity"]["MEDIUM"]}</div><div class="lbl">Medium</div></div>')
        html_parts.append(f'<div class="summary-card sc-low"><div class="num">{summary["vulnerabilities_by_severity"]["LOW"]}</div><div class="lbl">Low</div></div>')
        html_parts.append(f'<div class="summary-card sc-info"><div class="num">{summary["vulnerabilities_by_severity"]["INFO"]}</div><div class="lbl">Info</div></div>')
        html_parts.append('</div>')

        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            vulns = vulns_by_severity[severity]
            sev_class = severity.lower()
            html_parts.append(f'<div class="severity-section"><div class="severity-header sh-{sev_class}">')
            html_parts.append(f'{severity} <span class="count">{len(vulns)}</span></div>')
            if not vulns:
                html_parts.append('<div class="none-found">No vulnerabilities found</div>')
            else:
                for v in vulns:
                    html_parts.append(f'<div class="vuln-card">')
                    html_parts.append(f'<h3>{v.name}</h3>')
                    html_parts.append(f'<div class="desc">{v.description}</div>')
                    html_parts.append(f'<div class="meta">')
                    html_parts.append(f'<div class="mi"><strong>URL:</strong> {v.url}</div>')
                    html_parts.append(f'<div class="mi"><strong>Parameter:</strong> {v.parameter}</div>')
                    html_parts.append(f'<div class="mi"><strong>CVSS:</strong> {v.cvss_score}</div>')
                    html_parts.append(f'<div class="mi"><strong>Confidence:</strong> {v.confidence:.0%}</div>')
                    html_parts.append(f'<div class="mi"><strong>Module:</strong> {v.module}</div>')
                    html_parts.append(f'</div>')
                    if v.payload:
                        safe_payload = v.payload.replace("<", "&lt;").replace(">", "&gt;")
                        html_parts.append(f'<div class="payload-box">{safe_payload}</div>')
                    html_parts.append(f'<div class="impact-box">{vuln_impact(v.name, v.module)}</div>')
                    if v.evidence:
                        safe_evidence = v.evidence[:500].replace("<", "&lt;").replace(">", "&gt;")
                        html_parts.append(f'<div class="evidence">{safe_evidence}</div>')
                    if v.remediation:
                        html_parts.append(f'<div class="remediation">{v.remediation}</div>')
                    html_parts.append('</div>')
            html_parts.append('</div>')

        html_parts.append(f'<div class="footer">Generated by CyberSecurity Vulnerability Scanner Professional Edition &middot; Author: ARIF &middot; {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>')
        html_parts.append('</div></body></html>')

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(html_parts))

        self.logger.info(f"HTML report generated: {filepath}")
        return filepath

    def _generate_json(self, result: ScanResult, scan_dir: str) -> str:
        filepath = os.path.join(scan_dir, "full_report.json")
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(result.to_dict(), f, indent=2, default=str)
        self.logger.info(f"JSON report generated: {filepath}")
        return filepath

    def _generate_txt(self, result: ScanResult, scan_dir: str) -> str:
        filepath = os.path.join(scan_dir, "short_report.txt")
        summary = result.summary

        lines = []
        lines.append("=" * 70)
        lines.append("  CYBERSECURITY VULNERABILITY SCANNER - SCAN REPORT")
        lines.append("=" * 70)
        lines.append("")
        lines.append(f"  Target:           {result.target}")
        lines.append(f"  Scan ID:          {result.scan_id}")
        lines.append(f"  Date:             {datetime.fromtimestamp(result.start_time).strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"  Duration:         {result.duration:.1f} seconds")
        lines.append(f"  Total Requests:   {result.total_requests}")
        lines.append(f"  Modules Ran:      {len(result.modules_ran)}")
        lines.append("")
        lines.append("-" * 70)
        lines.append("  VULNERABILITY SUMMARY")
        lines.append("-" * 70)
        lines.append(f"  CRITICAL:  {summary['vulnerabilities_by_severity']['CRITICAL']}")
        lines.append(f"  HIGH:      {summary['vulnerabilities_by_severity']['HIGH']}")
        lines.append(f"  MEDIUM:    {summary['vulnerabilities_by_severity']['MEDIUM']}")
        lines.append(f"  LOW:       {summary['vulnerabilities_by_severity']['LOW']}")
        lines.append(f"  INFO:      {summary['vulnerabilities_by_severity']['INFO']}")
        lines.append(f"  TOTAL:     {summary['vulnerabilities_by_severity']['total']}")
        lines.append("")

        if result.vulnerabilities:
            lines.append("-" * 70)
            lines.append("  DETAILED FINDINGS")
            lines.append("-" * 70)
            for i, v in enumerate(result.vulnerabilities, 1):
                lines.append("")
                lines.append(f"  [{i}] {v.name}")
                lines.append(f"  {'-' * 50}")
                lines.append(f"  Severity:   {v.severity.value} (CVSS: {v.cvss_score})")
                lines.append(f"  URL:        {v.url}")
                lines.append(f"  Parameter:  {v.parameter}")
                lines.append(f"  Payload:    {v.payload[:100]}")
                lines.append(f"  Confidence: {v.confidence:.0%}")
                lines.append(f"  Module:     {v.module}")
                if v.evidence:
                    lines.append(f"  Evidence:   {v.evidence[:200]}")
                if v.remediation:
                    lines.append(f"  Remediation: {v.remediation}")

        lines.append("")
        lines.append("=" * 70)
        lines.append(f"  Generated by CyberSecurity Vulnerability Scanner | Author: ARIF")
        lines.append(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 70)

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))

        self.logger.info(f"TXT report generated: {filepath}")
        return filepath
