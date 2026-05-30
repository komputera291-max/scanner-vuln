"""
Directory/File Enumeration Module
Author: ARIF
"""

import asyncio
import logging
from typing import List, Optional, Dict
from urllib.parse import urljoin
from core.requester import Requester


class DirectoryEnum:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.requester = Requester(config)
        self.results_lock = asyncio.Lock()

    async def enumerate(self, target: str, wordlist: Optional[List[str]] = None) -> Dict[str, int]:
        self.logger.info(f"Starting directory enumeration for {target}")
        target = target.rstrip('/')
        found = {}

        directories = wordlist or [
            # Admin & Management
            "admin", "administrator", "manage", "management", "manager",
            "control", "panel", "dashboard", "cpanel", "whm", "plesk",
            "directadmin", "webmin", "usermin", "virtualmin",
            # Authentication
            "login", "signin", "signup", "register", "logout", "forgot",
            "reset", "reset-password", "forgot-password", "auth", "oauth",
            "saml", "sso", "cas", "openid", "2fa", "otp", "mfa",
            # API & Development
            "api", "api/v1", "api/v2", "api/v3", "rest", "graphql",
            "swagger", "docs", "documentation", "openapi", "spec",
            "developer", "developers", "dev", "devhub", "sandbox",
            # Configuration
            "config", "configuration", "configure", "setup", "install",
            ".env", ".git", ".git/config", ".gitignore", ".htaccess",
            "web.config", "app.config", "config.php", "config.json",
            # Database
            "db", "database", "mysql", "phpmyadmin", "pma", "adminer",
            "phppgadmin", "phpadmin", "sql", "sqlite", "mongo-express",
            # Files & Uploads
            "upload", "uploads", "file", "files", "download", "downloads",
            "media", "static", "assets", "img", "images", "css", "js",
            # Backup
            "backup", "backups", "dump", "dump.sql", "backup.sql",
            ".bak", "old", "new", "temp", "tmp", "archive", "archives",
            # Security
            "security", "secure", "private", "protected", "restricted",
            "secret", "secrets", "hidden", "internal", "staff",
            # System
            "server-status", "server-info", "status", "health",
            "healthcheck", "health-check", "info", "phpinfo", "phpinfo.php",
            "test", "tests", "debug", "error", "errors", "log", "logs",
            # Application specific
            "wp-admin", "wp-content", "wp-includes", "wp-json",
            "administrator", "components", "modules", "plugins",
            "themes", "includes", "templates", "cache", "caches",
            # Common web paths
            "robots.txt", "sitemap.xml", "sitemap", "crossdomain.xml",
            "favicon.ico", "humans.txt", "security.txt",
            # Frameworks
            "actuator", "actuator/health", "actuator/info",
            "actuator/env", "actuator/beans", "actuator/mappings",
            "actuator/metrics", "actuator/auditevents",
            # Cloud & Infrastructure
            ".aws", ".azure", ".gcp", ".google", "cloud",
            "docker", "dockerfile", "docker-compose.yml",
            "kubernetes", "k8s", ".kube", "kubeconfig",
            # Other common
            "cgi-bin", "cgi", "scripts", "cron", "jobs",
            "proxy", "vpn", "remote", "rdp", "ssh",
            "webmail", "mail", "email", "smtp", "imap", "pop3",
            "owa", "exchange", "autodiscover",
            "xmlrpc.php", "xmlrpc", "soap", "wsdl",
            "index.php", "index.html", "index.htm", "default.aspx",
            "shell", "cmd", "command", "exec", "execute",
            "payload", "exploit", "webshell", "backdoor",
            "eval", "assert", "system", "passthru",
            "phpinfo.php", "info.php", "test.php", "php.php",
            "editor", "ckeditor", "fckeditor", "tinymce",
            "elfinder", "filemanager", "file-manager",
            "class", "classes", "lib", "libs", "library", "libraries",
            "vendor", "vendors", "third-party", "thirdparty",
            "node_modules", "bower_components", "packages",
            "dist", "build", "src", "source", "app",
            "models", "views", "controllers", "controllers",
            "routes", "router", "middleware", "middlewares",
            "helpers", "helpers", "utils", "utilities",
            "services", "providers", "factories", "repositories",
            "migrations", "seeds", "seeders", "factories"
        ]

        semaphore = asyncio.Semaphore(self.config.get("threading", {}).get("max_threads", 20))

        async def check_path(path: str) -> None:
            async with semaphore:
                try:
                    url = urljoin(target + "/", path.lstrip("/"))
                    response = await self.requester.get(url, timeout=10)
                    if response:
                        status = response.status
                        if status in [200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403, 500]:
                            async with self.results_lock:
                                found[url] = status
                except Exception:
                    pass

        tasks = [check_path(d) for d in directories]
        await asyncio.gather(*tasks)

        self.logger.info(f"Found {len(found)} accessible paths on {target}")
        return found
