"""
API Endpoint Discovery Module
Author: ARIF
"""

import asyncio
import logging
import re
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse
from core.requester import Requester
from core.parser import ResponseParser


class EndpointDiscovery:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.requester = Requester(config)
        self.parser = ResponseParser(config)
        self.results_lock = asyncio.Lock()

    async def discover(self, target: str) -> Dict:
        self.logger.info(f"Starting API endpoint discovery for {target}")
        result = {
            "endpoints": [],
            "api_paths": [],
            "js_endpoints": [],
            "api_docs": []
        }

        try:
            response = await self.requester.get(target)
            if not response:
                return result
            html = await response.text()

            endpoints = self.parser.extract_api_endpoints(html, target)
            result["endpoints"] = endpoints
            result["js_endpoints"] = self._extract_from_js(endpoints, target)

            common_api_paths = [
                "/api", "/api/v1", "/api/v2", "/api/v3", "/api/v4", "/api/v5",
                "/rest", "/rest/v1", "/rest/v2",
                "/graphql", "/graphiql", "/voyager",
                "/swagger.json", "/swagger", "/swagger-ui",
                "/api-docs", "/api/documentation",
                "/openapi.json", "/openapi.yaml",
                "/.well-known/ai-plugin.json",
                "/api/swagger.json", "/api/docs",
                "/api/openapi.json", "/api/swagger.yaml",
                "/v1", "/v2", "/v3",
                "/api/health", "/api/status", "/api/ping",
                "/api/users", "/api/user", "/api/login", "/api/logout",
                "/api/token", "/api/refresh", "/api/auth",
                "/api/items", "/api/posts", "/api/products",
                "/api/categories", "/api/orders", "/api/carts",
                "/api/config", "/api/settings", "/api/admin",
                "/api/search", "/api/query", "/api/export",
                "/api/import", "/api/upload", "/api/files",
                "/api/reports", "/api/analytics", "/api/metrics",
                "/api/logs", "/api/errors", "/api/debug",
                "/api/cache", "/api/clear", "/api/reset",
                "/api/webhook", "/api/webhooks", "/api/callback",
                "/api/register", "/api/verify", "/api/validate",
                "/api/reset-password", "/api/forgot-password",
                "/api/profile", "/api/account", "/api/session",
                "/api/notifications", "/api/messages", "/api/chats",
                "/api/comments", "/api/reviews", "/api/ratings",
                "/api/tags", "/api/tag", "/api/categories",
                "/api/media", "/api/images", "/api/files",
                "/api/documents", "/api/download", "/api/upload",
                "/api/export", "/api/import", "/api/sync",
                "/api/backup", "/api/restore", "/api/migrate",
                "/cgi-bin/", "/cgi", "/bin/",
                "/ws", "/websocket", "/socket.io",
                "/sockjs", "/stomp", "/mqtt",
                "/soap", "/soap/", "/xmlrpc.php",
                "/rpc", "/jsonrpc", "/json-rpc",
                "/trpc", "/grpc",
                "/actuator", "/actuator/health", "/actuator/info",
                "/actuator/env", "/actuator/beans", "/actuator/mappings",
                "/actuator/metrics", "/actuator/auditevents",
                "/actuator/httptrace", "/actuator/threaddump",
                "/actuator/heapdump", "/actuator/loggers",
                "/actuator/scheduledtasks", "/actuator/conditions",
                "/actuator/configprops", "/actuator/shutdown",
                "/health", "/healthcheck", "/ready", "/live",
                "/info", "/ping", "/status", "/version",
                "/metrics", "/prometheus", "/metrics/prometheus",
                "/favicon.ico", "/robots.txt", "/sitemap.xml",
                "/.env", "/.git/config", "/.gitignore",
                "/config.json", "/config.yaml", "/config.yml",
                "/package.json", "/composer.json", "/requirements.txt",
                "/Dockerfile", "/docker-compose.yml",
                "/nginx.conf", "/web.config", "/.htaccess",
                "/crossdomain.xml", "/clientaccesspolicy.xml",
                "/phpinfo.php", "/info.php", "/test.php",
                "/server-status", "/server-info", "/server-info/",
                "/.well-known/", "/.well-known/security.txt",
                "/.well-known/assetlinks.json",
                "/.well-known/apple-app-site-association",
                "/.well-known/change-password",
                "/.well-known/openid-configuration",
                "/.well-known/oauth-authorization-server",
                "/.well-known/webfinger",
                "/.well-known/jwks.json",
                "/.well-known/dnt-policy.txt",
                "/.well-known/gpc.json",
                "/.well-known/interest-group.txt",
                "/.well-known/nodeinfo",
                "/.well-known/host-meta",
                "/.well-known/host-meta.json",
                "/.well-known/timezone",
                "/.well-known/matrix",
                "/.well-known/autoconfig/mail",
                "/.well-known/mta-sts.txt",
                "/.well-known/sshfp",
                "/.well-known/pki-validation",
                "/.well-known/private-pkcs7-chain.txt",
                "/.well-known/carddav",
                "/.well-known/caldav",
                "/.well-known/robots.txt",
                "/.well-known/traffic-advice",
                "/.well-known/repute-template",
                "/.well-known/reputation",
                "/.well-known/security.txt",
                "/api/.well-known/",
                "/api/swagger.json",
                "/api/v1/openapi.json",
                "/api/v2/openapi.json",
                "/api/graphql",
                "/swagger-resources",
                "/swagger-ui.html",
                "/swagger-ui/index.html",
                "/v2/api-docs",
                "/v3/api-docs",
                "/springfox/api-docs",
                "/api/doc",
                "/api/docs/",
                "/api/v1/api-docs",
                "/api/v2/api-docs",
                "/api/v3/api-docs",
                "/openapi",
                "/openapi.json",
                "/openapi.yaml",
                "/openapi.yml",
            ]

            for path in common_api_paths:
                try:
                    url = urljoin(target.rstrip('/') + '/', path.lstrip('/'))
                    resp = await self.requester.get(url, timeout=8)
                    if resp and resp.status in [200, 201, 202, 301, 302, 401, 403]:
                        content_length = len(await resp.text()) if resp.status == 200 else 0
                        path_type = self._classify_path(path, resp.status, content_length)
                        if path_type == "api_docs":
                            result["api_docs"].append(url)
                        else:
                            result["api_paths"].append({
                                "url": url,
                                "status": resp.status,
                                "type": path_type,
                                "length": content_length
                            })
                except Exception:
                    pass

        except Exception as e:
            self.logger.error(f"Endpoint discovery error: {e}")

        return result

    def _classify_path(self, path: str, status: int, length: int) -> str:
        if any(doc in path.lower() for doc in ["swagger", "openapi", "api-docs", "api/doc"]):
            return "api_docs"
        if "graphql" in path.lower():
            return "graphql"
        if any(act in path.lower() for act in ["actuator", "health", "info", "metrics"]):
            return "actuator"
        if any(env in path.lower() for env in [".env", ".git", "config"]):
            return "config_exposure"
        if status == 200 and length > 0:
            return "active_endpoint"
        if status in [401, 403]:
            return "authenticated_endpoint"
        return "endpoint"

    def _extract_from_js(self, endpoints: List[str], target: str) -> List[str]:
        js_endpoints = []
        for ep in endpoints:
            if '.js' in ep or 'javascript' in ep:
                js_endpoints.append(ep)
        return js_endpoints
