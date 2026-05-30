"""
Response Parser — extract data, analyze responses
Author: ARIF
"""

import re
import json
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
import logging


class ResponseParser:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config

    def extract_text(self, html: str) -> str:
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for script in soup(["script", "style"]):
                script.decompose()
            return soup.get_text(separator=' ', strip=True)
        except Exception:
            return re.sub(r'<[^>]+>', ' ', html)

    def extract_scripts(self, html: str) -> List[str]:
        scripts = []
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for script in soup.find_all('script'):
                src = script.get('src')
                if src:
                    scripts.append(src)
                content = script.string
                if content:
                    scripts.append(content[:200])
        except Exception as e:
            self.logger.debug(f"Error extracting scripts: {e}")
        return scripts

    def extract_comments(self, html: str) -> List[str]:
        comments = []
        pattern = r'<!--(.*?)-->'
        matches = re.findall(pattern, html, re.DOTALL)
        for match in matches:
            stripped = match.strip()
            if stripped and len(stripped) > 5:
                comments.append(stripped)
        return comments

    def extract_js_vars(self, html: str) -> Dict[str, str]:
        vars_dict = {}
        patterns = [
            r'(?:var|let|const)\s+(\w+)\s*=\s*["\']([^"\']+)["\']',
            r'(\w+)\s*:\s*["\']([^"\']+)["\']',
            r'api[Kk]ey\s*[:=]\s*["\']([^"\']+)["\']',
            r'token\s*[:=]\s*["\']([^"\']+)["\']'
        ]
        for pattern in patterns:
            matches = re.findall(pattern, html)
            for key, value in matches:
                vars_dict[key] = value
        return vars_dict

    def extract_metatags(self, html: str) -> Dict[str, str]:
        meta = {}
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for tag in soup.find_all('meta'):
                name = tag.get('name') or tag.get('property', '')
                content = tag.get('content', '')
                if name and content:
                    meta[name.lower()] = content
        except Exception:
            pass
        return meta

    def analyze_response_diff(self, base_response: str, test_response: str) -> Dict[str, Any]:
        analysis = {
            "length_diff": len(test_response) - len(base_response),
            "contains_keywords": [],
            "status_changed": False,
            "similarity": 0.0
        }
        if not base_response or not test_response:
            return analysis
        analysis["similarity"] = self._calculate_similarity(base_response, test_response)
        return analysis

    def _calculate_similarity(self, a: str, b: str) -> float:
        if not a or not b:
            return 0.0
        a_words = set(a.lower().split())
        b_words = set(b.lower().split())
        if not a_words or not b_words:
            return 0.0
        intersection = a_words.intersection(b_words)
        union = a_words.union(b_words)
        return len(intersection) / len(union)

    def extract_error_messages(self, html: str) -> List[str]:
        error_patterns = [
            r'(?:Warning|Error|Notice|Fatal|Exception|Parse|Syntax):\s*[^<]+',
            r'(?:SQL|MySQL|PostgreSQL|ORA-|MSSQL|sqlite)[^<]{10,100}',
            r'(?:stack trace|Stack trace|at\s+\w+\.\w+)',
            r'([A-Z]\w+Exception)[^<]{10,100}',
            r'(?:include|require|require_once|include_once)[^<]{10,100}',
            r'(?:file_get_contents|fopen|fread|file_put_contents)[^<]{10,100}',
            r'(?:undefined index|undefined variable|undefined offset)',
            r'(?:PDOException|mysqli_error|mysql_error)',
            r'(?:Division by zero|Call to undefined)',
            r'(?:Class \'[^\']+\' not found)',
            r'(?:Invalid argument supplied for foreach)'
        ]
        found = []
        for pattern in error_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            found.extend(matches[:3])
        return list(set(found))

    def has_sqli_error(self, html: str) -> bool:
        patterns = [
            r'SQL\s+syntax.*?MySQL',
            r'Warning.*?mysql_',
            r'MySQLSyntaxErrorException',
            r'PostgreSQL.*?ERROR',
            r'Warning.*?pg_',
            r'Uncaught.*?mysqli_sql_exception',
            r'ORA-\d{5}',
            r'SQLite3::',
            r'you have an error in your sql',
            r'Microsoft.*?ODBC.*?SQL Server',
            r'syntax error.*?SQL',
            r'MySqli_Exception',
            r'PDOException.*?SQL',
            r'\[SQL Server\]',
            r'Incorrect syntax near',
            r'Unclosed quotation mark',
            r'Microsoft OLE DB Provider for ODBC Drivers'
        ]
        html_lower = html.lower()
        for pattern in patterns:
            if re.search(pattern, html, re.IGNORECASE):
                return True
        if "sql" in html_lower and ("error" in html_lower or "exception" in html_lower or "warning" in html_lower):
            return True
        return False

    def has_xss_reflected(self, html: str, payload: str) -> bool:
        if not payload or not html:
            return False
        check_payload = payload.replace('+', ' ').replace('%3C', '<').replace('%3E', '>')
        check_payload = check_payload.replace('%22', '"').replace('%27', "'")
        check_payload = check_payload.replace('&lt;', '<').replace('&gt;', '>')
        check_payload = check_payload.replace('&quot;', '"').replace('&#x27;', "'")
        if check_payload in html:
            return True
        escaped = re.escape(check_payload[:50])
        if re.search(escaped, html, re.IGNORECASE):
            return True
        return False

    def has_lfi_success(self, html: str) -> bool:
        indicators = [
            r'root:.*?:0:0:',
            r'daemon:.*?:1:1:',
            r'bin:.*?:2:2:',
            r'www-data:',
            r'nobody:',
            r'\[boot loader\]',
            r'\[fonts\]',
            r'\[extensions\]',
            r'Windows Registry Editor',
            r'SYSTEM\\.*?CurrentControlSet',
            r'<?xml version="1.0"',
            r'# MySQL dump',
            r'# phpMyAdmin',
            r'DB_HOST',
            r'DB_PASSWORD',
            r'define\(\'DB_',
            r'\$db\[\''
        ]
        for pattern in indicators:
            if re.search(pattern, html, re.IGNORECASE):
                return True
        return False

    def detect_cms(self, html: str, headers: Dict[str, str]) -> Dict[str, str]:
        cms = {}
        indicators = {
            "WordPress": [
                r'wp-content', r'wp-includes', r'wp-admin',
                r'WordPress', r'/wp-json/', r'generator.*WordPress'
            ],
            "Joomla": [
                r'com_content', r'com_modules', r'com_users',
                r'Joomla', r'joomla', r'formation-sct'
            ],
            "Drupal": [
                r'drupal', r'Drupal', r'node/\d+', r'user/\d+',
                r'misc/drupal', r'sites/all'
            ],
            "Magento": [
                r'Magento', r'magento', r'skin/frontend',
                r'js/mage', r'media/catalog'
            ],
            "Laravel": [
                r'Laravel', r'laravel', r'_token',
                r'csrf-token.*content='
            ],
            "CodeIgniter": [
                r'CodeIgniter', r'ci_session', r'ci_csrf_token'
            ],
            "Shopify": [
                r'Shopify', r'myshopify\.com', r'/cdn/shop/'
            ],
            "PrestaShop": [
                r'PrestaShop', r'prestashop', r'id_lang'
            ]
        }
        html_lower = html.lower()
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        for cms_name, patterns in indicators.items():
            score = 0
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    score += 2
                if re.search(pattern.lower(), html_lower):
                    score += 1
            for k, v in headers_lower.items():
                if cms_name.lower() in v:
                    score += 3
                    if 'x-powered-by' in k:
                        score += 2
                if 'x-generator' == k and cms_name.lower() in v:
                    score += 5
            if score >= 2:
                cms[cms_name] = {"confidence": min(100, score * 10), "score": score}
        return cms

    def detect_framework(self, html: str, headers: Dict[str, str]) -> Dict[str, str]:
        frameworks = {}
        indicators = {
            "React": [r'react\.js', r'react-dom', r'data-reactroot', r'data-reactid'],
            "Angular": [r'ng-app', r'angular\.js', r'ng-version', r'[ng-controller]'],
            "Vue.js": [r'vue\.js', r'v-bind', r'v-model', r'v-if', r'v-for'],
            "jQuery": [r'jquery', r'\$\(', r'jQuery\(', r'jquery-'],
            "Bootstrap": [r'bootstrap\.css', r'bootstrap\.js', r'col-md-', r'col-xs-'],
            "Tailwind": [r'tailwindcss', r'class="[^"]* (?:flex|grid|container|mx-auto)'],
            "Next.js": [r'__NEXT_DATA__', r'next\.js', r'/_next/static'],
            "Nuxt.js": [r'__NUXT__', r'nuxt\.js', r'/_nuxt/'],
            "Express": [r'x-powered-by.*express', r'express'],
            "Django": [r'csrftoken', r'django', r'__django__'],
            "Flask": [r'flask', r'flask-session'],
            "Spring": [r'spring', r'java\.*?spring', r'X-Application-Context']
        }
        html_lower = html.lower()
        for fw_name, patterns in indicators.items():
            score = 0
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    score += 2
            for k, v in headers.items():
                k_lower = k.lower()
                v_lower = v.lower()
                if fw_name.lower() in v_lower:
                    score += 2
                if 'x-powered-by' == k_lower and fw_name.lower() in v_lower:
                    score += 3
            if score >= 1:
                frameworks[fw_name] = {"confidence": min(100, score * 15), "score": score}
        return frameworks

    def detect_server_tech(self, headers: Dict[str, str]) -> Dict[str, str]:
        tech = {}
        server_header = headers.get('Server', headers.get('server', ''))
        if server_header:
            tech['server'] = server_header
        x_powered = headers.get('X-Powered-By', headers.get('x-powered-by', ''))
        if x_powered:
            tech['x_powered_by'] = x_powered
        for header in ['x-aspnet-version', 'X-AspNet-Version']:
            val = headers.get(header, '')
            if val:
                tech['asp.net'] = val
        for header in ['x-aspnetmvc-version', 'X-AspNetMvc-Version']:
            val = headers.get(header, '')
            if val:
                tech['asp.net_mvc'] = val
        return tech

    def extract_api_endpoints(self, html: str, base_url: str) -> List[str]:
        endpoints = []
        patterns = [
            r'["\'](?:/api/[\w/.\-?=&]+)["\']',
            r'["\'](?:/v\d+/[\w/.\-?=&]+)["\']',
            r'["\'](?:/graphql)["\']',
            r'["\'](?:/rest/[\w/.\-?=&]+)["\']',
            r'(?:api|rest|graphql|v\d)[\w/.\-?=&]+',
            r'url:\s*["\']([^"\']+)["\']',
            r'href=["\'](/api/[^"\']+)["\']',
            r'action=["\']([^"\']+)["\']'
        ]
        for pattern in patterns:
            matches = re.findall(pattern, html)
            for match in matches:
                if match.startswith('/'):
                    from urllib.parse import urljoin
                    endpoints.append(urljoin(base_url, match))
                elif match.startswith(('http://', 'https://')):
                    endpoints.append(match)
                elif '/' in match:
                    from urllib.parse import urljoin
                    endpoints.append(urljoin(base_url, '/' + match.lstrip('/')))
        return list(set(endpoints))

    def analyze_cookies(self, cookies: Dict[str, str], headers: Dict[str, str]) -> List[Dict]:
        results = []
        set_cookie = headers.get('Set-Cookie', headers.get('set-cookie', ''))
        if not set_cookie:
            return results
        cookie_entries = set_cookie.split('\n')
        for entry in cookie_entries:
            if not entry.strip():
                continue
            analysis = {
                "name": "",
                "has_secure": False,
                "has_httponly": False,
                "has_samesite": False,
                "samesite_value": "",
                "has_path": False,
                "has_domain": False,
                "has_expires": False,
                "is_persistent": False,
                "issues": []
            }
            parts = entry.split(';')
            if '=' in parts[0]:
                analysis['name'] = parts[0].split('=')[0].strip()
            for part in parts[1:]:
                part = part.strip().lower()
                if part == 'secure':
                    analysis['has_secure'] = True
                elif part == 'httponly':
                    analysis['has_httponly'] = True
                elif part.startswith('samesite'):
                    analysis['has_samesite'] = True
                    if '=' in part:
                        analysis['samesite_value'] = part.split('=')[1].strip()
                elif part.startswith('path'):
                    analysis['has_path'] = True
                elif part.startswith('domain'):
                    analysis['has_domain'] = True
                elif part.startswith('expires') or part.startswith('max-age'):
                    analysis['has_expires'] = True
                    analysis['is_persistent'] = True
            if not analysis['has_secure']:
                analysis['issues'].append("Missing Secure flag - cookie can be sent over HTTP")
            if not analysis['has_httponly']:
                analysis['issues'].append("Missing HttpOnly flag - cookie accessible via JavaScript")
            if analysis['has_samesite'] and analysis['samesite_value'] == 'none':
                analysis['issues'].append("SameSite=None - cookie sent on cross-site requests")
            if analysis['is_persistent']:
                analysis['issues'].append("Persistent cookie - consider session-only cookies")
            results.append(analysis)
        return results

    def find_sensitive_data(self, text: str) -> List[Dict]:
        sensitive = []
        patterns = [
            ("API Key / Token", r'["\']?(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)["\']?\s*[:=]\s*["\']([^"\']{16,})["\']'),
            ("AWS Access Key", r'(?:AKIA[0-9A-Z]{16})'),
            ("AWS Secret Key", r'["\']?[a-zA-Z0-9\/+=]{40}["\']?(?:\s*["\']?(?:aws_secret|secret_access_key))'),
            ("Private Key", r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
            ("JWT Token", r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}'),
            ("OAuth Token", r'ya29\.[a-zA-Z0-9_-]{50,}'),
            ("GitHub Token", r'(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}'),
            ("Google API Key", r'AIza[0-9A-Za-z\-_]{35}'),
            ("Stripe API Key", r'sk_live_[0-9a-zA-Z]{24,}'),
            ("Slack Token", r'xox[baprs]-[0-9a-zA-Z\-]{10,}'),
            ("Facebook Token", r'EAACEdEose0cBA[0-9a-zA-Z]{40,}'),
            ("Twitter Token", r'[1-9][0-9]+-[a-zA-Z0-9]{40}'),
            ("Heroku API Key", r'[hH][eE][rR][oO][kK][uU].*?[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}'),
            ("Generic Secret", r'["\']?(?:secret|password|passwd|pwd)["\']?\s*[:=]\s*["\']([^"\']{8,})["\']'),
            ("Database URL", r'(?:mysql|postgres|mongodb|redis|elasticsearch)://[^\s"\']+'),
            ("IP Address", r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            ("Email", r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'),
            ("Phone Number", r'\b(?:\+?[0-9]{1,3}[-. ]?)?\(?[0-9]{2,4}\)?[-. ]?[0-9]{2,4}[-. ]?[0-9]{3,4}\b'),
            ("Credit Card", r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'),
            ("SSN (US)", r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b')
        ]
        for data_type, pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches[:5]:
                if isinstance(match, tuple):
                    match = match[0]
                if len(match) > 3:
                    sensitive.append({
                        "type": data_type,
                        "value": match[:50] + "..." if len(match) > 50 else match,
                        "pattern": pattern[:30] + "..."
                    })
        return sensitive
