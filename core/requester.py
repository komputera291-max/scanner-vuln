"""
HTTP Request Handler with proxy, UA rotation, and retry logic
Author: ARIF
"""

import asyncio
import random
import logging
from typing import Dict, Optional, Any, List
from urllib.parse import urlparse, urljoin
import aiohttp
from aiohttp_socks import ProxyConnector
import ssl


class Requester:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.timeout = aiohttp.ClientTimeout(
            total=config.get("requests", {}).get("timeout", 30)
        )
        self.max_retries = config.get("requests", {}).get("max_retries", 3)
        self.user_agents = self._load_user_agents()
        self.session = None
        self.proxy_list = config.get("requests", {}).get("proxy_list", [])
        self.current_proxy_index = 0
        self.cookies = {}
        self.headers = self._default_headers()

    def _default_headers(self) -> Dict[str, str]:
        return {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "max-age=0",
            "TE": "trailers"
        }

    def _load_user_agents(self) -> List[str]:
        return [
            # Chrome Desktop
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/118.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/117.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/116.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/115.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/114.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/113.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/112.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/111.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/110.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/109.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/118.0.0.0 Safari/537.36",
            # Firefox Desktop
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:118.0) Gecko/20100101 Firefox/118.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:117.0) Gecko/20100101 Firefox/117.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:116.0) Gecko/20100101 Firefox/116.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:114.0) Gecko/20100101 Firefox/114.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:113.0) Gecko/20100101 Firefox/113.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:112.0) Gecko/20100101 Firefox/112.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:111.0) Gecko/20100101 Firefox/111.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Mozilla/5.0 (X11; Debian; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Mozilla/5.0 (X11; CentOS; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Mozilla/5.0 (X11; Linux i686; rv:120.0) Gecko/20100101 Firefox/120.0",
            # Safari Desktop
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.1 Safari/605.1.15",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 Version/16.6 Safari/605.1.15",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 Version/15.6 Safari/605.1.15",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/605.1.15 Version/14.1 Safari/605.1.15",
            # Edge Desktop
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/118.0.0.0 Safari/537.36 Edg/118.0.2088.69",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.47",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
            # Opera Desktop
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/118.0.0.0 Safari/537.36 OPR/104.0.0.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
            # Brave Desktop
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 Brave/1.60",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 Brave/1.60",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 Brave/1.60",
            # Vivaldi Desktop
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 Vivaldi/6.4",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 Vivaldi/6.4",
            # iPhone / iOS
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0_3 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 15_8 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 Version/17.1 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0_3 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1",
            # iPad / iPadOS
            "Mozilla/5.0 (iPad; CPU OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
            "Mozilla/5.0 (iPad; CPU OS 17_0_3 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
            "Mozilla/5.0 (iPad; CPU OS 16_7_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
            "Mozilla/5.0 (iPad; CPU OS 15_8 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
            "Mozilla/5.0 (iPad; CPU OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 Version/17.1 Mobile/15E148 Safari/604.1",
            # iPod
            "Mozilla/5.0 (iPod touch; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
            "Mozilla/5.0 (iPod touch; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
            # Android Chrome
            "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 Chrome/120.0.6099.43 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/120.0.6099.43 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 14; Pixel 7 Pro) AppleWebKit/537.36 Chrome/120.0.6099.43 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 Chrome/120.0.6099.43 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 14; Pixel 6 Pro) AppleWebKit/537.36 Chrome/120.0.6099.43 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 14; Pixel 6) AppleWebKit/537.36 Chrome/120.0.6099.43 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 Chrome/120.0.6099.43 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 14; SM-S926B) AppleWebKit/537.36 Chrome/120.0.6099.43 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 Chrome/120.0.6099.43 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 13; SM-S906B) AppleWebKit/537.36 Chrome/120.0.6099.43 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36 Chrome/120.0.6099.43 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 13; Pixel 7 Pro) AppleWebKit/537.36 Chrome/119.0.6045.163 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Chrome/119.0.6045.163 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 Chrome/119.0.6045.163 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 13; SM-S906B) AppleWebKit/537.36 Chrome/119.0.6045.163 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 12; SM-G998B) AppleWebKit/537.36 Chrome/119.0.6045.163 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 12; SM-G996B) AppleWebKit/537.36 Chrome/119.0.6045.163 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 12; SM-G991B) AppleWebKit/537.36 Chrome/119.0.6045.163 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 12; Pixel 6 Pro) AppleWebKit/537.36 Chrome/119.0.6045.163 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 Chrome/119.0.6045.163 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 11; SM-G998B) AppleWebKit/537.36 Chrome/119.0.6045.163 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 Chrome/119.0.6045.163 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 11; Pixel 4 XL) AppleWebKit/537.36 Chrome/119.0.6045.163 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 Chrome/119.0.6045.163 Mobile Safari/537.36",
            # Android Firefox
            "Mozilla/5.0 (Android 14; Mobile; rv:120.0) Gecko/120.0 Firefox/120.0",
            "Mozilla/5.0 (Android 13; Mobile; rv:120.0) Gecko/120.0 Firefox/120.0",
            "Mozilla/5.0 (Android 12; Mobile; rv:119.0) Gecko/119.0 Firefox/119.0",
            "Mozilla/5.0 (Android 11; Mobile; rv:118.0) Gecko/118.0 Firefox/118.0",
            # Android Samsung Browser
            "Mozilla/5.0 (Linux; Android 14; SAMSUNG SM-S928B) AppleWebKit/537.36 Chrome/120.0.6099.43 Mobile Safari/537.36 SamsungBrowser/24.0",
            "Mozilla/5.0 (Linux; Android 13; SAMSUNG SM-S908B) AppleWebKit/537.36 Chrome/119.0.6045.163 Mobile Safari/537.36 SamsungBrowser/23.0",
            # Android WebView
            "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro Build/UP1A) AppleWebKit/537.36 Version/4.0 Chrome/120.0.6099.43 Mobile Safari/537.36",
            # Chrome OS
            "Mozilla/5.0 (X11; CrOS x86_64 15393.58.0) AppleWebKit/537.36 Chrome/119.0.6045.212 Safari/537.36",
            "Mozilla/5.0 (X11; CrOS x86_64 15183.69.0) AppleWebKit/537.36 Chrome/118.0.5993.117 Safari/537.36",
            "Mozilla/5.0 (X11; CrOS armv7l 15183.69.0) AppleWebKit/537.36 Chrome/118.0.5993.117 Safari/537.36",
            # Linux other browsers
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/534.34 Version/5.0 Konqueror/4.14",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 Midori/11.0",
            # Windows older
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 Chrome/109.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
            "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 Chrome/109.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
            "Mozilla/5.0 (Windows NT 6.1; rv:109.0) Gecko/20100101 Firefox/115.0",
            # Bots & Crawlers
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "Mozilla/5.0 (compatible; Yandexbot/3.0; +http://yandex.com/bots)",
            "Mozilla/5.0 (compatible; DuckDuckBot/1.0; +http://duckduckgo.com/duckduckbot.html)",
            "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
            "Mozilla/5.0 (compatible; SemrushBot/7.0; +http://www.semrush.com/bot.html)",
            "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
            "Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://majestic12.co.uk/bot.php)",
            "Mozilla/5.0 (compatible; Seznambot/1.0; +http://www.seznam.cz/bot.html)",
            "Mozilla/5.0 (compatible; Sogou spider; +http://www.sogou.com/docs/help/webmaster.htm)",
            "Mozilla/5.0 (compatible; Exabot/3.0; +http://www.exabot.com/go/robot)",
            "Mozilla/5.0 (compatible; DotBot/1.1; +https://opensiteexplorer.org/dotbot; +help@moz.com)",
            "Mozilla/5.0 (compatible; Screaming Frog SEO Spider/19.0; +https://www.screamingfrog.co.uk/seo-spider/)",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 (compatible; Google-Apps-Script)",
            "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 Chrome/120.0.6099.44 Mobile Safari/537.36 (compatible; Google-InspectionTool)",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 (compatible; Google-Site-Verification/1.0)",
            "Mozilla/5.0 (compatible; APT-Client/1.0; +https://apt-client-bot.com)",
            "Mozilla/5.0 (compatible; Wget/1.21; linux-gnu)",
            "curl/8.4.0",
            "Wget/1.21.3 (linux-gnu)",
            "python-requests/2.31.0",
            "Python-urllib/3.11",
            "okhttp/4.12.0",
            # Windows 11 Edge Chromium
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 Edg/120.0.2210.91",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 Edg/120.0.2210.89",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36 Edg/119.0.2151.72",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36 Edg/119.0.2151.58",
            # Internet Explorer
            "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
            "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
            "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko",
            "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko",
            "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; .NET4.0C; .NET4.0E; rv:11.0) like Gecko",
            # Mobile other browsers
            "Mozilla/5.0 (Linux; Android 14; K) AppleWebKit/537.36 Chrome/120.0.6099.44 Mobile Safari/537.36 DuckDuckGo/5",
            "Mozilla/5.0 (iPad; CPU OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 Version/17.1 Mobile/15E148 Safari/604.1 OPT/7.4",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 Version/17.1 Mobile/15E148 Safari/604.1 Focus/17.0",
            # Opera Mobile
            "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 Chrome/120.0.6099.43 Mobile Safari/537.36 OPR/80.0.4170.0",
            # Puffin
            "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 Chrome/120.0.6099.43 Mobile Safari/537.36 Puffin/10.0.0.12345",
            # UC Browser
            "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 Chrome/120.0.6099.43 Mobile Safari/537.36 UCBrowser/13.5.0.1308",
            # Nokia
            "Mozilla/5.0 (Linux; Android 10; Nokia 6.1) AppleWebKit/537.36 Chrome/119.0.6045.163 Mobile Safari/537.36",
            # OnePlus
            "Mozilla/5.0 (Linux; Android 13; OnePlus 11) AppleWebKit/537.36 Chrome/120.0.6099.43 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 13; OnePlus 10 Pro) AppleWebKit/537.36 Chrome/119.0.6045.163 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 12; OnePlus 9 Pro) AppleWebKit/537.36 Chrome/119.0.6045.163 Mobile Safari/537.36",
            # Xiaomi
            "Mozilla/5.0 (Linux; Android 14; Xiaomi 14 Pro) AppleWebKit/537.36 Chrome/120.0.6099.43 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 13; Xiaomi 13 Pro) AppleWebKit/537.36 Chrome/119.0.6045.163 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 12; Mi 11) AppleWebKit/537.36 Chrome/119.0.6045.163 Mobile Safari/537.36",
            # Huawei
            "Mozilla/5.0 (Linux; Android 14; Huawei P60 Pro) AppleWebKit/537.36 Chrome/120.0.6099.43 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 13; Huawei Mate 50 Pro) AppleWebKit/537.36 Chrome/119.0.6045.163 Mobile Safari/537.36",
            # Oppo / Vivo / Realme
            "Mozilla/5.0 (Linux; Android 14; OPPO Find X7) AppleWebKit/537.36 Chrome/120.0.6099.43 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 13; vivo X90 Pro) AppleWebKit/537.36 Chrome/119.0.6045.163 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 13; realme GT 3) AppleWebKit/537.36 Chrome/119.0.6045.163 Mobile Safari/537.36",
            # Sony
            "Mozilla/5.0 (Linux; Android 13; Sony Xperia 1 V) AppleWebKit/537.36 Chrome/119.0.6045.163 Mobile Safari/537.36",
            # LG
            "Mozilla/5.0 (Linux; Android 12; LG Velvet) AppleWebKit/537.36 Chrome/119.0.6045.163 Mobile Safari/537.36",
            # Motorola
            "Mozilla/5.0 (Linux; Android 14; Motorola Edge 50 Pro) AppleWebKit/537.36 Chrome/120.0.6099.43 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 13; Motorola Edge 40) AppleWebKit/537.36 Chrome/119.0.6045.163 Mobile Safari/537.36",
            # Windows Phone
            "Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1; Microsoft; Lumia 950) AppleWebKit/537.36 Chrome/52.0.2743.116 Mobile Safari/537.36 Edge/15.15063",
            "Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1; Nokia; Lumia 650) AppleWebKit/537.36 Chrome/52.0.2743.116 Mobile Safari/537.36 Edge/15.15063",
            # Playstation
            "Mozilla/5.0 (PlayStation 5 2.00) AppleWebKit/537.36 Chrome/94.0.4606.81 Safari/537.36",
            "Mozilla/5.0 (PlayStation 4 10.00) AppleWebKit/537.36 Chrome/94.0.4606.81 Safari/537.36",
            # Xbox
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 Edge/120.0.2210.91 Xbox",
            # Nintendo Switch
            "Mozilla/5.0 (Nintendo Switch; WebApplet) AppleWebKit/609.1.20",
            # Smart TV
            "Mozilla/5.0 (SMART-TV; Linux; Tizen 6.0) AppleWebKit/537.36 Chrome/96.0.4664.93 Safari/537.36",
            "Mozilla/5.0 (Web0S; Linux/SmartTV) AppleWebKit/537.36 Chrome/95.0.4638.69 Safari/537.36 webOS.TV-2022",
            "Mozilla/5.0 (Linux; Android 12; Android TV) AppleWebKit/537.36 Chrome/96.0.4664.93 Safari/537.36",
            # Apple TV
            "Mozilla/5.0 (Apple TV; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15",
            # Google TV / Chromecast
            "Mozilla/5.0 (Linux; Android 12; Chromecast) AppleWebKit/537.36 Chrome/96.0.4664.93 Safari/537.36",
            # Wear OS
            "Mozilla/5.0 (Linux; Android 14; Wear OS) AppleWebKit/537.36 Chrome/120.0.6099.43 Mobile Safari/537.36"
        ]

    async def _create_session(self) -> aiohttp.ClientSession:
        connector = None
        if self.config.get("proxy", {}).get("enabled"):
            proxy_config = self.config["proxy"]
            proxy_url = f"{proxy_config['protocol']}://{proxy_config['host']}:{proxy_config['port']}"
            if proxy_config.get("username"):
                proxy_url = f"{proxy_config['protocol']}://{proxy_config['username']}:{proxy_config['password']}@{proxy_config['host']}:{proxy_config['port']}"
            connector = ProxyConnector.from_url(proxy_url)
        else:
            ssl_context = ssl.create_default_context()
            if not self.config.get("requests", {}).get("verify_ssl", True):
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
            connector = aiohttp.TCPConnector(ssl=ssl_context)

        return aiohttp.ClientSession(
            timeout=self.timeout,
            connector=connector,
            cookies=self.cookies
        )

    def _random_ua(self) -> str:
        return random.choice(self.user_agents)

    def _build_headers(self, custom_headers: Optional[Dict] = None) -> Dict[str, str]:
        headers = {**self.headers}
        if self.config.get("requests", {}).get("user_agent_rotation", True):
            headers["User-Agent"] = self._random_ua()
        else:
            headers["User-Agent"] = self.user_agents[0]
        if custom_headers:
            headers.update(custom_headers)
        return headers

    async def request(self, method: str, url: str,
                      params: Optional[Dict] = None,
                      data: Optional[Any] = None,
                      json_data: Optional[Dict] = None,
                      headers: Optional[Dict] = None,
                      allow_redirects: bool = True,
                      cookies: Optional[Dict] = None) -> Optional[aiohttp.ClientResponse]:
        last_error = None
        for attempt in range(self.max_retries):
            session = None
            try:
                session = await self._create_session()
                request_headers = self._build_headers(headers)
                async with session.request(
                    method=method,
                    url=url,
                    params=params,
                    data=data,
                    json=json_data,
                    headers=request_headers,
                    allow_redirects=allow_redirects,
                    cookies=cookies,
                ) as response:
                    await response.read()
                    return response
            except asyncio.TimeoutError:
                last_error = "Timeout"
                await asyncio.sleep(1 * (attempt + 1))
            except aiohttp.ClientError as e:
                last_error = str(e)
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(0.5 * (attempt + 1))
            except Exception as e:
                last_error = str(e)
                break
            finally:
                if session and not session.closed:
                    await session.close()
        self.logger.debug(f"Request failed after {self.max_retries} attempts: {url} - {last_error}")
        return None

    async def get(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        return await self.request("POST", url, **kwargs)

    async def head(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        return await self.request("OPTIONS", url, **kwargs)

    async def put(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        return await self.request("PUT", url, **kwargs)

    async def extract_forms(self, url: str, html: str) -> List[Dict]:
        from bs4 import BeautifulSoup
        forms = []
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for form in soup.find_all('form'):
                form_data = {
                    "action": form.get('action', '') or url,
                    "method": form.get('method', 'get').upper(),
                    "inputs": []
                }
                base_url = url
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_data = {
                        "name": input_tag.get('name', ''),
                        "type": input_tag.get('type', 'text'),
                        "value": input_tag.get('value', '')
                    }
                    if input_data["name"]:
                        form_data["inputs"].append(input_data)
                form_data["action"] = urljoin(base_url, form_data["action"])
                forms.append(form_data)
        except Exception as e:
            self.logger.debug(f"Error extracting forms: {e}")
        return forms

    async def extract_links(self, url: str, html: str) -> List[str]:
        from bs4 import BeautifulSoup
        links = []
        try:
            soup = BeautifulSoup(html, 'html.parser')
            base_url = url
            for tag in soup.find_all(['a', 'link', 'script', 'img', 'iframe', 'frame']):
                attr = 'href' if tag.name in ['a', 'link'] else 'src'
                link = tag.get(attr)
                if link and not link.startswith(('javascript:', 'mailto:', 'tel:', '#')):
                    absolute = urljoin(base_url, link)
                    if absolute.startswith(('http://', 'https://')):
                        links.append(absolute)
            for tag in soup.find_all('form'):
                action = tag.get('action')
                if action:
                    absolute = urljoin(base_url, action)
                    if absolute.startswith(('http://', 'https://')):
                        links.append(absolute)
        except Exception as e:
            self.logger.debug(f"Error extracting links: {e}")
        return list(set(links))

    async def extract_parameters(self, url: str) -> Dict[str, str]:
        parsed = urlparse(url)
        params = {}
        if parsed.query:
            for param in parsed.query.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    params[key] = value
                else:
                    params[param] = ""
        return params

    async def close(self) -> None:
        pass
