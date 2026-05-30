"""
CMS Detection Module
Author: ARIF
"""

import asyncio
import logging
import re
from typing import Dict, List, Optional
from urllib.parse import urlparse, urljoin
from core.requester import Requester
from core.parser import ResponseParser


class CmsDetect:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.requester = Requester(config)
        self.parser = ResponseParser(config)
        self.results_lock = asyncio.Lock()

    async def detect(self, target: str) -> Dict:
        self.logger.info(f"Starting CMS detection for {target}")
        result = {"cms": [], "framework": [], "server_tech": {}}
        try:
            response = await self.requester.get(target)
            if not response:
                return result
            html = await response.text()
            headers = {k: v for k, v in response.headers.items()}

            result["server_tech"] = self.parser.detect_server_tech(headers)
            result["cms"] = self.parser.detect_cms(html, headers)
            result["framework"] = self.parser.detect_framework(html, headers)

            await self._check_version_files(target, result)

        except Exception as e:
            self.logger.error(f"CMS detection error: {e}")
        return result

    async def _check_version_files(self, target: str, result: Dict) -> None:
        version_checks = {
            "WordPress": [
                ("/wp-content/themes/", 'themes'),
                ("/wp-content/plugins/", 'plugins'),
                ("/wp-includes/version.php", r'\$wp_version\s*=\s*[\'"](\d+\.\d+(?:\.\d+)?)[\'"]'),
                ("/readme.html", r'WordPress\s+(\d+\.\d+(?:\.\d+)?)'),
                ("/feed/", r'WordPress\s+(\d+\.\d+(?:\.\d+)?)')
            ],
            "Joomla": [
                ("/administrator/manifests/files/joomla.xml", r'<version>(\d+\.\d+(?:\.\d+)?)</version>'),
                ("/components/com_", 'component'),
                ("/modules/mod_", 'module')
            ],
            "Drupal": [
                ("/CHANGELOG.txt", r'Drupal\s+(\d+\.\d+(?:\.\d+)?)'),
                ("/core/CHANGELOG.txt", r'Drupal\s+(\d+\.\d+(?:\.\d+)?)'),
                ("/core/authorize.php", 'drupal')
            ],
            "Magento": [
                ("/magento_version", r'(\d+\.\d+(?:\.\d+)?)'),
                ("/skin/frontend/", 'magento_skin'),
                ("/static/version", r'version(\d+)')
            ],
            "Laravel": [
                ("/mix-manifest.json", 'laravel_mix'),
                ("/api/", 'laravel_api')
            ]
        }

        for cms_name, checks in version_checks.items():
            if cms_name.lower() in str(result.get("cms", {})).lower():
                for path, pattern in checks:
                    try:
                        url = urljoin(target, path)
                        resp = await self.requester.get(url)
                        if resp:
                            content = await resp.text()
                            if isinstance(pattern, str):
                                if pattern in content:
                                    if cms_name not in result:
                                        result.setdefault("version_files", {})
                                        result["version_files"][cms_name] = path
                    except Exception:
                        pass
        return result
