"""
Technology Stack Detection Module
Author: ARIF
"""

import asyncio
import logging
import re
from typing import Dict, List, Optional
from urllib.parse import urlparse, urljoin
from core.requester import Requester
from core.parser import ResponseParser


class TechDetect:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.requester = Requester(config)
        self.parser = ResponseParser(config)
        self.results_lock = asyncio.Lock()

    async def detect(self, target: str) -> Dict:
        self.logger.info(f"Starting technology detection for {target}")
        result = {
            "server": {},
            "cdn": [],
            "analytics": [],
            "javascript_libs": [],
            "css_frameworks": [],
            "web_servers": [],
            "programming_languages": []
        }

        try:
            response = await self.requester.get(target)
            if not response:
                return result
            html = await response.text()
            headers = {k: v for k, v in response.headers.items()}

            for k, v in headers.items():
                k_lower = k.lower()

                if k_lower == 'server':
                    result["web_servers"].append(v)
                    self._detect_programming_lang(v, result)

                if k_lower == 'x-powered-by':
                    result["programming_languages"].append(v)
                    self._detect_programming_lang(v, result)

                if k_lower == 'set-cookie':
                    for cookie in v.split('\n'):
                        cookie_lower = cookie.lower()
                        if 'cloudflare' in cookie_lower:
                            result["cdn"].append("Cloudflare")
                        if 'akamai' in cookie_lower:
                            result["cdn"].append("Akamai")
                        if 'incapsula' in cookie_lower:
                            result["cdn"].append("Incapsula")
                        if 'fastly' in cookie_lower:
                            result["cdn"].append("Fastly")

            if 'cf-ray' in headers:
                result["cdn"].append("Cloudflare")
            if 'x-sucuri-id' in headers or 'x-sucuri-cache' in headers:
                result["cdn"].append("Sucuri")
            if 'x-cdn' in headers:
                result["cdn"].append(headers['x-cdn'])
            if 'akamai-request-id' in headers:
                result["cdn"].append("Akamai")
            if 'x-amz-cf-id' in headers or 'x-amz-cf-pop' in headers:
                result["cdn"].append("AWS CloudFront")
            if 'x-fastly-request-id' in headers:
                result["cdn"].append("Fastly")
            if 'server' in headers and 'cloudflare' in headers['server'].lower():
                result["cdn"].append("Cloudflare")

            js_libs = []
            js_patterns = {
                "jQuery": r'jquery[.-](\d[\d.-]+)?(?:\.min)?\.js',
                "jQuery UI": r'jquery-ui[.-](\d[\d.-]+)?(?:\.min)?\.js',
                "jQuery Migrate": r'jquery-migrate[.-](\d[\d.-]+)?\.js',
                "React": r'react(?:\.development|\.production)?(?:\.min)?\.js',
                "ReactDOM": r'react-dom(?:\.development|\.production)?(?:\.min)?\.js',
                "Vue.js": r'vue(?:\.min)?\.js',
                "Angular": r'angular(?:\.min)?\.js',
                "AngularJS": r'angular[.-](?:\d[\d.-]+)?(?:\.min)?\.js',
                "Bootstrap JS": r'bootstrap(?:\.bundle)?(?:\.min)?\.js',
                "Lodash": r'lodash(?:\.min)?\.js',
                "Moment.js": r'moment(?:\.min)?\.js',
                "D3.js": r'd3(?:\.min)?\.js',
                "Chart.js": r'chart(?:\.min)?\.js',
                "GSAP": r'gsap(?:\.min)?\.js',
                "Three.js": r'three(?:\.min)?\.js',
                "Axios": r'axios(?:\.min)?\.js',
                "Socket.io": r'socket\.io(?:\.min)?\.js',
                "Alpine.js": r'alpine(?:\.min)?\.js',
                "HTMX": r'htmx(?:\.min)?\.js',
                "Turbo": r'turbo(?:\.min)?\.js',
                "Stimulus": r'stimulus(?:\.min)?\.js',
                "Next.js": r'next\.js|__NEXT_DATA__',
                "Nuxt.js": r'nuxt\.js|__NUXT__',
                "Gatsby": r'gatsby\.js|___gatsby',
                "Svelte": r'svelte\.js|__SVELTE__',
                "Ember.js": r'ember\.js|ember(?:\.min)?\.js',
                "Backbone.js": r'backbone(?:\.min)?\.js',
                "Marionette": r'marionette(?:\.min)?\.js',
                "Underscore": r'underscore(?:\.min)?\.js',
                "Mustache": r'mustache(?:\.min)?\.js',
                "Handlebars": r'handlebars(?:\.min)?\.js',
                "Modernizr": r'modernizr(?:\.custom)?\.js',
                "Polyfill": r'polyfill\.io|polyfill(?:\.min)?\.js',
                "SWR": r'swr(?:\.min)?\.js',
                "React Query": r'react-query(?:\.min)?\.js',
                "Zustand": r'zustand(?:\.min)?\.js',
                "Redux": r'redux(?:\.min)?\.js',
                "MobX": r'mobx(?:\.min)?\.js',
                "Recoil": r'recoil(?:\.min)?\.js',
                "Jotai": r'jotai(?:\.min)?\.js',
                "Valtio": r'valtio(?:\.min)?\.js',
                "Prism.js": r'prism(?:\.min)?\.js',
                "Highlight.js": r'highlight(?:\.min)?\.js',
                "SyntaxHighlighter": r'syntaxhighlighter(?:\.min)?\.js',
                "Swiper": r'swiper(?:\.min)?\.js',
                "Fancybox": r'fancybox(?:\.min)?\.js',
                "Lightbox": r'lightbox(?:\.min)?\.js',
                "Select2": r'select2(?:\.min)?\.js',
                "Selectize": r'selectize(?:\.min)?\.js',
                "Chosen": r'chosen(?:\.min)?\.js',
                "Datepicker": r'datepicker(?:\.min)?\.js',
                "Flatpickr": r'flatpickr(?:\.min)?\.js',
                "Datatables": r'datatables(?:\.min)?\.js',
                "TinyMCE": r'tinymce(?:\.min)?\.js',
                "CKEditor": r'ckeditor\.js|ckeditor5',
                "Summernote": r'summernote(?:\.min)?\.js',
                "Quill": r'quill(?:\.min)?\.js',
                "Dropzone": r'dropzone(?:\.min)?\.js',
                "Cropper": r'cropper(?:\.min)?\.js',
                "Isotope": r'isotope(?:\.min)?\.js',
                "Masonry": r'masonry(?:\.min)?\.js',
                "FullCalendar": r'fullcalendar(?:\.min)?\.js',
                "Leaflet": r'leaflet(?:\.min)?\.js',
                "Mapbox": r'mapbox-gl(?:\.min)?\.js',
                "Google Maps": r'maps\.googleapis\.com|google-maps',
                "OpenLayers": r'openlayers(?:\.min)?\.js',
                "Turf.js": r'turf(?:\.min)?\.js',
                "PDF.js": r'pdf\.js|pdfjs',
                "jsPDF": r'jspdf(?:\.min)?\.js',
                "FileSaver": r'filesaver(?:\.min)?\.js',
                "Clipboard.js": r'clipboard(?:\.min)?\.js',
                "Screenfull": r'screenfull(?:\.min)?\.js',
                "Animate.css": r'animate(?:\.min)?\.css',
                "Wow.js": r'wow(?:\.min)?\.js',
                "AOS": r'aos(?:\.min)?\.js',
                "Typed.js": r'typed(?:\.min)?\.js',
                "Particles.js": r'particles(?:\.min)?\.js',
                "ScrollReveal": r'scrollreveal(?:\.min)?\.js',
                "Parallax.js": r'parallax(?:\.min)?\.js',
                "Waypoints": r'waypoints(?:\.min)?\.js',
                "CountUp": r'countup(?:\.min)?\.js',
                "Owl Carousel": r'owl\.carousel(?:\.min)?\.js',
                "Slick Carousel": r'slick(?:\.min)?\.js',
                "Flickity": r'flickity(?:\.min)?\.js',
                "Swiper": r'swiper(?:\.min)?\.js',
            }
            for lib_name, pattern in js_patterns.items():
                if re.search(pattern, html, re.IGNORECASE):
                    js_libs.append(lib_name)
            result["javascript_libs"] = js_libs

            css_frameworks = []
            css_patterns = {
                "Bootstrap": r'bootstrap(?:\.min)?\.css',
                "Bootstrap 5": r'bootstrap(?:\.min)?\.css.*v5|bootstrap@5',
                "Bootstrap 4": r'bootstrap(?:\.min)?\.css.*v4|bootstrap@4',
                "Bootstrap 3": r'bootstrap(?:\.min)?\.css.*v3|bootstrap@3',
                "Tailwind CSS": r'tailwindcss|tailwind(?:\.min)?\.css',
                "Foundation": r'foundation(?:\.min)?\.css',
                "Bulma": r'bulma(?:\.min)?\.css',
                "Materialize": r'materialize(?:\.min)?\.css',
                "Semantic UI": r'semantic(?:\.min)?\.css',
                "PureCSS": r'pure(?:\.min)?\.css',
                "Spectre": r'spectre(?:\.min)?\.css',
                "Milligram": r'milligram(?:\.min)?\.css',
                "Skeleton": r'skeleton(?:\.min)?\.css',
                "Primer": r'primer(?:\.min)?\.css',
                "Open Props": r'open-props(?:\.min)?\.css',
                "Font Awesome": r'font-awesome(?:\.min)?\.css|fontawesome',
                "Material Icons": r'material-icons|materialdesignicons',
                "Ionicons": r'ionicons(?:\.min)?\.css',
                "Feather Icons": r'feather(?:\.min)?\.js',
                "Heroicons": r'heroicons',
                "Boxicons": r'boxicons(?:\.min)?\.css',
                "Line Awesome": r'line-awesome(?:\.min)?\.css',
            }
            for css_name, pattern in css_patterns.items():
                if re.search(pattern, html, re.IGNORECASE):
                    css_frameworks.append(css_name)
            result["css_frameworks"] = css_frameworks

            analytics = []
            analytics_patterns = {
                "Google Analytics": r'google-analytics\.com|ga\.js|gtag\.js|gtag\(|ga\(|_gaq',
                "Google Tag Manager": r'googletagmanager\.com/gtm\.js|_gtm',
                "Facebook Pixel": r'connect\.facebook\.net.*fbevents|fbq\(|facebook_pixel',
                "Hotjar": r'hotjar\.com|_hjSettings|hj\(\)',
                "Mixpanel": r'mixpanel\.com|mixpanel\.init|mpmetric',
                "Amplitude": r'amplitude\.com|amplitude\.init',
                "Segment": r'segment\.com/analytics|analytics\.js|analytics\.load',
                "Heap": r'heapanalytics\.com|heap\.load|heap\(\)',
                "FullStory": r'fullstory\.com|FS\(\)|_fs_',
                "Crazy Egg": r'crazegg\.com|ce\(\)',
                "Mouseflow": r'mouseflow\.com|_mfq',
                "Clicky": r'clicky\.com|clicky\.init',
                "Matomo": r'matomo\.js|_paq|piwik\.js',
                "HubSpot": r'js\.hs-scripts\.com|hsAnalytics|_hsq',
                "LinkedIn Insight": r'linkedin\.com/trk|_linkedin',
                "Twitter Pixel": r'static\.ads-twitter\.com|twttr\.conversion',
                "TikTok Pixel": r'tiktok\.com/pixel|_tiktok',
                "Pinterest Tag": r'ct\.pinterest\.com|_pinterest',
                "Reddit Pixel": r'alb\.reddit\.com|_reddit',
                "Snapchat Pixel": r'snap\.com/trk|_snapchat',
                "Bing Ads": r'bat\.bing\.com|_uetq',
                "Yandex Metrica": r'mc\.yandex\.ru|yaCounter|ym\(\)',
                "VWO": r'vwo\.com|_vwo_code|vwo\(\)',
                "Optimizely": r'optimizely\.com|optimizely\(\)|window\.optimizely',
                "AB Tasty": r'abtasty\.com|_abtasty',
                "Convert": r'convert\.com|_conv\(\)',
                "Kissmetrics": r'kissmetrics\.com|_kmq',
                "Woopra": r'woopra\.com|woopraTracker|_woopra',
                "Intercom": r'widget\.intercom\.io|Intercom\(\)',
                "Drift": r'drift\.com|drift\.load|drift\(\)',
                "Olark": r'olark\.com|olark\(\)|_olark',
                "LiveChat": r'livechat\.com|LiveChatWidget|__lc',
                "Tawk.to": r'tawk\.to|Tawk_API|Tawk_LoadStart',
                "Zendesk": r'zendesk\.com|zE\(\)|_zendesk',
                "Crisp": r'crisp\.chat|Crisp\(\)|$crisp',
                "Freshchat": r'freshchat\.com|freshchat\(\)|_freshchat',
                "SendGrid": r'sendgrid\.com|sendgrid\(\)',
                "Mailchimp": r'mailchimp\.com|mc4wp|_mchp',
                "ConvertKit": r'convertkit\.com|convertkit\(\)',
                "ActiveCampaign": r'activecampaign\.com|_act|act\(\)',
                "GetResponse": r'getresponse\.com|_getresponse',
                "AWeber": r'aweber\.com|_aweber',
            }
            for ana_name, pattern in analytics_patterns.items():
                if re.search(pattern, html, re.IGNORECASE):
                    analytics.append(ana_name)
            result["analytics"] = analytics

            cdn_detect = {
                "Cloudflare": r'cloudflare|cf-ray|cdn-cgi',
                "AWS CloudFront": r'cloudfront\.net|d\d+[a-z0-9]+\.cloudfront',
                "Fastly": r'fastly\.net|fastly-tls',
                "Akamai": r'akamai|akamaihd\.net|edgesuite\.net',
                "KeyCDN": r'keycdn\.com|kxcdn\.com',
                "StackPath": r'stackpathcdn\.com|stackpath\.com',
                "CDN77": r'cdn77\.com|cdn77\.net',
                "BunnyCDN": r'bunnycdn\.com|b-cdn\.net',
                "jsDelivr": r'cdn\.jsdelivr\.net',
                "cdnjs": r'cdnjs\.cloudflare\.com',
                "Google CDN": r'ajax\.googleapis\.com|fonts\.googleapis\.com',
                "Microsoft CDN": r'ajax\.aspnetcdn\.com|msdn\.microsoft\.com',
                "jQuery CDN": r'code\.jquery\.com',
                "Yandex CDN": r'yandex\.st|yastatic\.net',
                "Bootstrap CDN": r'cdn\.jsdelivr\.net/npm/bootstrap|stackpath\.bootstrapcdn\.com',
                "Font Awesome CDN": r'use\.fontawesome\.com|pro\.fontawesome\.com',
                "Unpkg": r'unpkg\.com',
                "ESM CDN": r'esm\.sh',
                "Skypack": r'cdn\.skypack\.dev',
                "Pika CDN": r'cdn\.pika\.dev',
            }
            for cdn_name, pattern in cdn_detect.items():
                if re.search(pattern, html, re.IGNORECASE) or any(
                    re.search(pattern, v, re.IGNORECASE) for v in headers.values()
                ):
                    if cdn_name not in result["cdn"]:
                        result["cdn"].append(cdn_name)

        except Exception as e:
            self.logger.error(f"Tech detection error: {e}")

        return result

    def _detect_programming_lang(self, header_value: str, result: Dict) -> None:
        lang_map = {
            "PHP": r'php|PHP',
            "ASP.NET": r'asp\.net|ASP\.NET|\.NET',
            "Node.js": r'node\.js|Node\.js|NodeJS',
            "Python": r'python|Django|Flask|Pyramid',
            "Ruby": r'ruby|Rails|Ruby on Rails',
            "Java": r'java|Java|Spring|Tomcat|JBoss|Jetty|WebLogic|WebSphere',
            "Go": r'go|golang|Golang',
            "Rust": r'rust|Rust|Actix|Rocket',
            "Elixir": r'elixir|Phoenix|Elixir',
            "Perl": r'perl|Perl|Catalyst|Mojolicious',
            "ColdFusion": r'coldfusion|ColdFusion|CFML',
            "Scala": r'scala|Scala|Lift|Play!',
            "Kotlin": r'kotlin|Ktor|Kotlin',
            "Deno": r'deno|Deno'
        }
        for lang, pattern in lang_map.items():
            if re.search(pattern, header_value, re.IGNORECASE):
                if lang not in result["programming_languages"]:
                    result["programming_languages"].append(lang)
