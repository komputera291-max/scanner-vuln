"""
CyberSecurity Vulnerability Scanner Professional Edition
Author: ARIF
Main Entry — Interactive Menu + CLI args
Usage:
  python scanner.py                              (interactive menu)
  python scanner.py --target https://example.com --full-scan
  python scanner.py --target https://example.com --module sqli,xss,lfi
  python scanner.py --target https://example.com --quick-scan
"""

import asyncio
import os
import sys
import time
import json
import random
import argparse
import logging
from datetime import datetime
from typing import List, Optional, Dict

# ANSI Colors
R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
B = "\033[94m"
M = "\033[95m"
C = "\033[96m"
W = "\033[97m"
N = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

VERSION = "3.0.0"
AUTHOR = "ARIF"


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def print_banner():
    banner = f"""
{BOLD}{C}  ============================================================
  {W}CYBERSECURITY VULNERABILITY SCANNER{C}
  {W}Professional Edition v{VERSION}{C}
  {W}Author: {AUTHOR}{C}
  ============================================================{N}
"""
    print(banner)


def print_menu():
    menu = f"""
{BOLD}{C}==================== MAIN MENU ===================={N}

  {Y}[1]{W}  Full Scan           {DIM}- All-in-one complete vuln scan{N}
  {Y}[2]{W}  Quick Scan          {DIM}- Basic security check (fast){N}
  {Y}[3]{W}  Custom Scan         {DIM}- Choose specific modules{N}

{B}  ----- SCANNER MODULES -----{W}
  {Y}[4]{W}  SQL Injection             {Y}[13]{W} File Upload
  {Y}[5]{W}  XSS (Reflected/Stored)   {Y}[14]{W} IDOR
  {Y}[6]{W}  LFI / RFI                {Y}[15]{W} Broken Auth
  {Y}[7]{W}  Command Injection        {Y}[16]{W} Sensitive Data
  {Y}[8]{W}  SSRF                     {Y}[17]{W} CORS
  {Y}[9]{W}  SSTI                     {Y}[18]{W} Security Headers
  {Y}[10]{W} XXE                      {Y}[19]{W} Cookie Security
  {Y}[11]{W} CSRF Token               {Y}[20]{W} SSL/TLS
  {Y}[12]{W} Open Redirect            {Y}[21]{W} Server Info

{B}  ----- RECONNAISSANCE -----{W}
  {Y}[22]{W} Subdomain Enumeration
  {Y}[23]{W} Directory / File Enumeration
  {Y}[24]{W} CMS Detection & Version
  {Y}[25]{W} Technology Stack Detection
  {Y}[26]{W} API Endpoint Discovery

{B}  ----- REPORT -----{W}
  {Y}[27]{W} View Last Scan Result
  {Y}[28]{W} Export Report (HTML / JSON / TXT)

{B}  ----- CONFIG -----{W}
  {Y}[29]{W} Settings & Configuration
  {Y}[30]{W} About & Help

  {Y}[0]{W}  Exit Scanner

{BOLD}{C}===================================================={N}
"""
    print(menu)


def print_module_menu():
    menu = f"""
{BOLD}{C}=============== CUSTOM SCAN MODULES ==============={N}

  {Y}[a]{W}  SQL Injection        {Y}[k]{W}  Open Redirect
  {Y}[b]{W}  XSS                  {Y}[l]{W}  File Upload
  {Y}[c]{W}  LFI/RFI              {Y}[m]{W}  IDOR
  {Y}[d]{W}  Command Injection    {Y}[n]{W}  Broken Auth
  {Y}[e]{W}  SSRF                 {Y}[o]{W}  Sensitive Data
  {Y}[f]{W}  SSTI                 {Y}[p]{W}  CORS
  {Y}[g]{W}  XXE                  {Y}[q]{W}  Security Headers
  {Y}[h]{W}  CSRF                 {Y}[r]{W}  Cookie Security
  {Y}[i]{W}  Server Info          {Y}[s]{W}  SSL/TLS
  {Y}[j]{W}  Subdomain Enums      {Y}[t]{W}  Directory Enum
  {Y}[u]{W}  CMS Detection        {Y}[v]{W}  Tech Detection
  {Y}[w]{W}  API Discovery        {Y}[x]{W}  ALL MODULES

  {DIM}Example: a,b,c,d,e (or 'x' for all){N}

{BOLD}{C}===================================================={N}
"""
    print(menu)


def format_time(seconds):
    if seconds < 60:
        return f"{seconds:.1f}s"
    mins = int(seconds // 60)
    secs = int(seconds % 60)
    return f"{mins}m {secs}s"


def print_progress(current, total, bar_length=40):
    if total == 0:
        return
    percent = current / total
    filled = int(bar_length * percent)
    bar = f"{G}{'█' * filled}{DIM}{'░' * (bar_length - filled)}{N}"
    print(f"\r  {Y}Progress:{N} {bar} {W}{int(percent * 100)}%{N} ({current}/{total})", end="")


def print_vuln(vuln, index=1):
    sev = vuln.get("severity", "INFO")
    if sev == "CRITICAL":
        color = f"{BOLD}{R}"
        tag = "CRITICAL"
    elif sev == "HIGH":
        color = R
        tag = "HIGH"
    elif sev == "MEDIUM":
        color = Y
        tag = "MEDIUM"
    elif sev == "LOW":
        color = B
        tag = "LOW"
    else:
        color = G
        tag = "INFO"

    print(f"\n  {color}[{tag}]{N} {BOLD}{vuln.get('name', 'Unknown')}{N}")
    print(f"  {DIM}URL:{N} {vuln.get('url', 'N/A')}")
    print(f"  {DIM}Parameter:{N} {vuln.get('parameter', 'N/A')}")
    if vuln.get("payload"):
        print(f"  {DIM}Payload:{N} {vuln.get('payload', '')[:80]}")
    if vuln.get("evidence"):
        print(f"  {DIM}Evidence:{N} {vuln.get('evidence', '')[:120]}")
    if vuln.get("remediation"):
        print(f"  {DIM}Fix:{N} {G}{vuln.get('remediation', '')[:120]}{N}")
    print(f"  {DIM}Confidence:{N} {vuln.get('confidence', 0):.0%}  {DIM}CVSS:{N} {vuln.get('cvss_score', 0)}")


async def run_scan(target: str, modules: Optional[List[str]] = None,
                   scan_mode: str = "full") -> Dict:
    from core.engine import ScanningEngine
    from core.reporter import ReportGenerator

    engine = ScanningEngine()
    reporter = ReportGenerator(engine.config)

    print(f"\n{C}[TARGET]{N} {W}{target}{N}")
    print(f"{C}[MODE]{N} {W}{scan_mode.upper()} SCAN{N}")
    print(f"{C}[STATUS]{N} {Y}Scanning...{N}\n")

    if modules is None:
        if scan_mode == "quick":
            modules = ["headers", "cookie", "server", "ssl", "sensitive"]
        elif scan_mode == "custom":
            pass
        else:
            modules = list(engine.modules.keys())

    start_time = time.time()
    result = await engine.run_scan(target, modules=modules)
    elapsed = time.time() - start_time

    print(f"\n{C}==================== SCAN COMPLETE ===================={N}")
    print(f"  {W}Duration:{N} {format_time(elapsed)}")
    print(f"  {W}Requests:{N} {result.total_requests}")
    print(f"  {W}Vulnerabilities:{N} {len(result.vulnerabilities)}")

    severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for v in result.vulnerabilities:
        severity_count[v.severity.value] += 1

    print(f"\n  {BOLD}Severity Breakdown:{N}")
    for sev, color in [("CRITICAL", f"{BOLD}{R}"), ("HIGH", R), ("MEDIUM", Y), ("LOW", B), ("INFO", G)]:
        if severity_count[sev] > 0:
            print(f"    {color}{sev}: {severity_count[sev]}{N}")

    if result.vulnerabilities:
        print(f"\n{R}Vulnerabilities Detected:{N}")
        for i, v in enumerate(result.vulnerabilities[:20], 1):
            print_vuln(v.to_dict(), i)
        if len(result.vulnerabilities) > 20:
            print(f"\n  {Y}... and {len(result.vulnerabilities) - 20} more vulnerabilities{N}")
    else:
        print(f"\n  {G}No vulnerabilities detected.{N}")

    if result.errors:
        print(f"\n  {Y}Errors: {len(result.errors)}{N}")
        for err in result.errors[:5]:
            print(f"    {DIM}{err}{N}")

    print(f"\n{C}Generating report...{N}")
    paths = reporter.generate_all(result)
    for fmt, path in paths.items():
        print(f"  {G}[{fmt.upper()}]{N} {path}")

    return result.to_dict()


async def main_async():
    import signal
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))

    parser = argparse.ArgumentParser(description="CyberSecurity Vulnerability Scanner")
    parser.add_argument("--target", "-t", help="Target URL to scan")
    parser.add_argument("--full-scan", action="store_true", help="Run full scan")
    parser.add_argument("--quick-scan", action="store_true", help="Run quick scan")
    parser.add_argument("--module", "-m", help="Specific modules (comma-separated)")
    parser.add_argument("--output", "-o", help="Output directory")

    args = parser.parse_args()

    if args.target:
        modules = None
        mode = "full"
        if args.module:
            modules = [m.strip() for m in args.module.split(",")]
            mode = "custom"
        elif args.quick_scan:
            mode = "quick"

        await run_scan(args.target, modules=modules, scan_mode=mode)
        return

    clear_screen()
    print_banner()

    last_result = None

    while True:
        print_menu()
        choice = input(f"\n  {B}[?]{W} Enter your choice {Y}[0-30]{W}: {N}").strip()

        if choice == "0":
            print(f"\n  {Y}Exiting scanner. Stay secure!{N}\n")
            break

        elif choice == "1":
            target = input(f"\n  {B}[?]{W} Enter target URL {Y}(https://example.com:443){W}: {N}").strip()
            if target:
                last_result = await run_scan(target, scan_mode="full")
            else:
                print(f"\n  {R}[!] Invalid target{N}")
            input(f"\n  {DIM}Press Enter to continue...{N}")

        elif choice == "2":
            target = input(f"\n  {B}[?]{W} Enter target URL {Y}(https://example.com:443){W}: {N}").strip()
            if target:
                last_result = await run_scan(target, scan_mode="quick")
            else:
                print(f"\n  {R}[!] Invalid target{N}")
            input(f"\n  {DIM}Press Enter to continue...{N}")

        elif choice == "3":
            print_module_menu()
            mod_choice = input(f"\n  {B}[?]{W} Enter module letters {Y}(example: a,b,c){W}: {N}").strip().lower()
            target = input(f"\n  {B}[?]{W} Enter target URL {Y}(https://example.com:443){W}: {N}").strip()

            if not target:
                print(f"\n  {R}[!] Invalid target{N}")
                input(f"\n  {DIM}Press Enter to continue...{N}")
                continue

            module_map = {
                'a': 'sqli', 'b': 'xss', 'c': 'lfi', 'd': 'cmdi', 'e': 'ssrf',
                'f': 'ssti', 'g': 'xxe', 'h': 'csrf', 'i': 'server', 'j': None,
                'k': 'redirect', 'l': 'upload', 'm': 'idor', 'n': 'auth',
                'o': 'sensitive', 'p': 'cors', 'q': 'headers', 'r': 'cookie',
                's': 'ssl', 't': None, 'u': None, 'v': None, 'w': None, 'x': None
            }

            if 'x' in mod_choice:
                modules = None
                mode = "full"
            else:
                selected = []
                for ch in mod_choice.replace(",", "").replace(" ", ""):
                    mod = module_map.get(ch)
                    if mod:
                        selected.append(mod)
                modules = selected if selected else None
                mode = "custom"

            last_result = await run_scan(target, modules=modules, scan_mode=mode)
            input(f"\n  {DIM}Press Enter to continue...{N}")

        elif choice.isdigit() and 4 <= int(choice) <= 26:
            module_choices = {
                "4": "sqli", "5": "xss", "6": "lfi", "7": "cmdi",
                "8": "ssrf", "9": "ssti", "10": "xxe", "11": "csrf",
                "12": "redirect", "13": "upload", "14": "idor", "15": "auth",
                "16": "sensitive", "17": "cors", "18": "headers", "19": "cookie",
                "20": "ssl", "21": "server", "22": None, "23": None,
                "24": None, "25": None, "26": None
            }
            mod = module_choices.get(str(choice))
            target = input(f"\n  {B}[?]{W} Enter target URL {Y}(https://example.com:443){W}: {N}").strip()
            if target and mod:
                last_result = await run_scan(target, modules=[mod], scan_mode="single")
            elif target and choice == "22":
                from recon.subdomain_enum import SubdomainEnum
                from core.engine import ScanningEngine
                engine = ScanningEngine()
                enum = SubdomainEnum(engine.config)
                print(f"\n  {Y}Enumerating subdomains...{N}")
                results = await enum.enumerate(target)
                print(f"\n  {G}Found {len(results)} subdomains:{N}")
                for r in results[:30]:
                    print(f"    {C}{r}{N}")
                last_result = {"target": target, "subdomains": results}
            elif target and choice == "23":
                from recon.directory_enum import DirectoryEnum
                from core.engine import ScanningEngine
                engine = ScanningEngine()
                denum = DirectoryEnum(engine.config)
                print(f"\n  {Y}Enumerating directories...{N}")
                results = await denum.enumerate(target)
                print(f"\n  {G}Found {len(results)} accessible paths:{N}")
                for url, status in sorted(results.items(), key=lambda x: x[1])[:30]:
                    color = G if status == 200 else Y if status in [301, 302] else R if status == 403 else W
                    print(f"    {color}[{status}]{N} {url}")
                last_result = {"target": target, "directories": results}
            elif target and choice == "24":
                from recon.cms_detect import CmsDetect
                from core.engine import ScanningEngine
                engine = ScanningEngine()
                cms = CmsDetect(engine.config)
                print(f"\n  {Y}Detecting CMS...{N}")
                results = await cms.detect(target)
                print(f"\n  {G}CMS Detection Results:{N}")
                if results.get("cms"):
                    for name, info in results["cms"].items():
                        conf = info.get("confidence", 0)
                        print(f"    {C}{name}{N} (confidence: {conf}%)")
                if results.get("framework"):
                    print(f"\n  {G}Frameworks:{N}")
                    for name, info in results["framework"].items():
                        conf = info.get("confidence", 0)
                        print(f"    {C}{name}{N} (confidence: {conf}%)")
                if results.get("server_tech"):
                    print(f"\n  {G}Server Tech:{N}")
                    for k, v in results["server_tech"].items():
                        print(f"    {k}: {v}")
                last_result = results
            elif target and choice == "25":
                from recon.tech_detect import TechDetect
                from core.engine import ScanningEngine
                engine = ScanningEngine()
                tech = TechDetect(engine.config)
                print(f"\n  {Y}Detecting technology stack...{N}")
                results = await tech.detect(target)
                for category, items in results.items():
                    if items:
                        print(f"\n  {G}{category.replace('_', ' ').title()}:{N}")
                        for item in items[:10]:
                            print(f"    {C}{item}{N}")
                last_result = results
            elif target and choice == "26":
                from recon.endpoint_discovery import EndpointDiscovery
                from core.engine import ScanningEngine
                engine = ScanningEngine()
                disc = EndpointDiscovery(engine.config)
                print(f"\n  {Y}Discovering API endpoints...{N}")
                results = await disc.discover(target)
                for cat, items in results.items():
                    if items:
                        print(f"\n  {G}{cat.replace('_', ' ').title()}:{N}")
                        for item in items[:15]:
                            if isinstance(item, dict):
                                print(f"    {C}[{item.get('status', '?')}]{N} {item.get('url', '')}")
                            else:
                                print(f"    {C}{item}{N}")
                last_result = results
            else:
                print(f"\n  {R}[!] Invalid target{N}")
            input(f"\n  {DIM}Press Enter to continue...{N}")

        elif choice == "27":
            if last_result:
                print(f"\n  {Y}Last Scan Result:{N}")
                target = last_result.get("target", "N/A")
                total_vulns = last_result.get("summary", {}).get("total_vulnerabilities", 0)
                print(f"  Target: {target}")
                print(f"  Total Vulnerabilities: {total_vulns}")
                if "vulnerabilities" in last_result:
                    for i, v in enumerate(last_result["vulnerabilities"][:10], 1):
                        print_vuln(v, i)
            else:
                print(f"\n  {Y}No scan results yet. Run a scan first.{N}")
            input(f"\n  {DIM}Press Enter to continue...{N}")

        elif choice == "28":
            if last_result:
                print(f"\n  {Y}Exporting report...{N}")
                from core.reporter import ReportGenerator
                from core.engine import ScanningEngine
                engine = ScanningEngine()
                from core.database import Database
                db = Database()
                scan_data = db.get_scan(last_result.get("scan_id", ""))
                if scan_data:
                    from core.engine import ScanResult
                    result = ScanResult(
                        target=last_result.get("target", ""),
                        start_time=last_result.get("start_time", time.time())
                    )
                    result.scan_id = last_result.get("scan_id", "")
                    for v in last_result.get("vulnerabilities", []):
                        from core.engine import Vulnerability, Severity
                        sev = Severity[v.get("severity", "INFO")]
                        vuln = Vulnerability(
                            name=v.get("name", ""),
                            description=v.get("description", ""),
                            severity=sev,
                            url=v.get("url", ""),
                            parameter=v.get("parameter", ""),
                            payload=v.get("payload", ""),
                            evidence=v.get("evidence", ""),
                            remediation=v.get("remediation", ""),
                            cvss_score=v.get("cvss_score", 0),
                            confidence=v.get("confidence", 0.5),
                            module=v.get("module", "")
                        )
                        result.add_vulnerability(vuln)
                    reporter = ReportGenerator(engine.config)
                    paths = reporter.generate_all(result)
                    for fmt, path in paths.items():
                        print(f"  {G}[{fmt.upper()}]{N} {path}")
                else:
                    print(f"\n  {Y}No stored results found. Run a scan first.{N}")
            else:
                print(f"\n  {Y}No scan results yet. Run a scan first.{N}")
            input(f"\n  {DIM}Press Enter to continue...{N}")

        elif choice == "29":
            print(f"\n  {Y}Settings & Configuration:{N}")
            print(f"\n  {C}[1]{W} Set threads (current: 20)")
            print(f"  {C}[2]{W} Set timeout (current: 30s)")
            print(f"  {C}[3]{W} Toggle proxy")
            print(f"  {C}[4]{W} Set output directory")
            print(f"  {C}[5]{W} View current config")
            print(f"  {C}[0]{W} Back")
            input(f"\n  {DIM}Press Enter to continue...{N}")

        elif choice == "30":
            print(f"\n  {C}ABOUT CYBERSECURITY VULNERABILITY SCANNER{N}")
            print(f"\n  {W}Version:{N} {VERSION}")
            print(f"  {W}Author:{N} {AUTHOR}")
            print(f"\n  {W}Description:{N}")
            print(f"  Professional web vulnerability scanner toolkit")
            print(f"  for Kali Linux / penetration testing.")
            print(f"\n  {W}Features:{N}")
            print(f"  - 20+ vulnerability scanner modules")
            print(f"  - 4+ million payload variations generator")
            print(f"  - False positive filter with confidence scoring")
            print(f"  - Multi-threading scanning engine")
            print(f"  - HTML/JSON/TXT report output")
            print(f"  - Interactive menu and CLI argument support")
            print(f"\n  {W}Modules:{N}")
            print(f"  SQLi, XSS, LFI/RFI, CMDi, SSRF, SSTI, XXE,")
            print(f"  CSRF, Open Redirect, File Upload, IDOR,")
            print(f"  Broken Auth, Sensitive Data, CORS, Headers,")
            print(f"  Cookies, SSL/TLS, Server Info,")
            print(f"  Subdomain Enum, Dir Enum, CMS Detect,")
            print(f"  Tech Detect, API Discovery")
            input(f"\n  {DIM}Press Enter to continue...{N}")

        else:
            print(f"\n  {R}[!] Invalid choice. Please enter a number from 0-30.{N}")
            input(f"\n  {DIM}Press Enter to continue...{N}")

        clear_screen()
        print_banner()


def main():
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print(f"\n\n  {Y}Scan interrupted by user.{N}\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n  {R}[ERROR]{N} {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
