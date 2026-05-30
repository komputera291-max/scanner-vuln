"""
Subdomain Enumeration Module
Author: ARIF
"""

import asyncio
import logging
import dns.resolver
import dns.exception
from typing import List, Dict, Optional
from urllib.parse import urlparse
from core.requester import Requester


class SubdomainEnum:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.requester = Requester(config)
        self.results_lock = asyncio.Lock()

    async def enumerate(self, target: str) -> List[str]:
        self.logger.info(f"Starting subdomain enumeration for {target}")
        parsed = urlparse(target)
        domain = (parsed.hostname or parsed.netloc.split(':')[0]).split('@')[-1].strip('[]').replace('www.', '')
        found = set()

        subdomains = [
            "www", "mail", "ftp", "admin", "blog", "shop", "api", "dev", "test",
            "stage", "staging", "beta", "demo", "vpn", "remote", "webmail",
            "secure", "portal", "cpanel", "whm", "support", "help", "docs",
            "status", "cdn", "static", "assets", "img", "images", "css", "js",
            "media", "video", "download", "downloads", "upload", "uploads",
            "backup", "monitor", "monitoring", "mysql", "db", "database",
            "redis", "memcached", "mongo", "elastic", "kibana", "grafana",
            "jenkins", "gitlab", "git", "svn", "jira", "confluence", "wiki",
            "owa", "autodiscover", "m", "mobile", "mobil", "wap", "iphone",
            "android", "app", "apps", "application", "my", "mypage",
            "members", "account", "accounts", "user", "users", "profile",
            "profiles", "site", "sites", "en", "fr", "de", "es", "it", "pt",
            "ru", "cn", "jp", "kr", "br", "ar", "in", "au", "ca", "uk", "nz",
            "sg", "hk", "tw", "th", "vn", "id", "ph", "my", "mx", "pl", "se",
            "no", "dk", "fi", "be", "ch", "at", "nl", "ie", "za", "eg", "ng",
            "ke", "ma", "tn", "dz", "jo", "lb", "qa", "sa", "ae", "ir", "pk",
            "bd", "lk", "np", "mm", "la", "kh", "mn", "uz", "kz", "az", "ge",
            "am", "by", "ua", "ro", "bg", "hr", "rs", "si", "sk", "cz", "hu",
            "lt", "lv", "ee", "is", "lu", "mt", "cy", "gr", "il", "tr", "kw",
            "bh", "om", "ye", "su", "ps", "af", "kyr", "tkm", "tjk",
            "web", "www2", "www3", "www4", "ww1", "ww2", "v2", "v3",
            "ns1", "ns2", "ns3", "ns4", "dns1", "dns2", "mx1", "mx2",
            "smtp", "pop3", "imap", "exchange", "owa", "autodiscover",
            "direct", "direct-connect", "connect", "community",
            "forum", "forums", "board", "boards", "chat", "talk",
            "discussion", "discussions", "groups", "group", "list",
            "lists", "mailman", "newsletter", "news", "feed", "feeds",
            "rss", "rss2", "atom", "xml", "json", "rest", "api", "soap",
            "wsdl", "swagger", "docs", "documentation", "wiki", "kb",
            "knowledgebase", "faq", "helpdesk", "ticket", "tickets",
            "bug", "bugs", "tracker", "mantis", "redmine", "taiga",
            "phabricator", "gerrit", "review", "code", "source",
            "sourcecode", "src", "raw", "blob", "tree", "commit",
            "svn", "cvs", "hg", "mercurial", "bitbucket", "github",
            "gitlab-ci", "ci", "cd", "build", "builder", "buildbot",
            "jenkins", "travis", "circle", "circleci", "teamcity",
            "bamboo", "artifactory", "nexus", "docker", "registry",
            "hub", "dockerhub", "k8s", "kubernetes", "kube", "minikube",
            "openshift", "cloud", "aws", "azure", "gcp", "google",
            "firebase", "heroku", "digitalocean", "linode", "vultr",
            "do", "ec2", "s3", "bucket", "storage", "files",
            "file", "data", "datacenter", "dc1", "dc2", "dc3",
            "server1", "server2", "server3", "server", "servers",
            "node1", "node2", "node3", "web1", "web2", "web3",
            "app1", "app2", "app3", "db1", "db2", "db3",
            "cache", "caching", "memcache", "varnish", "squid",
            "proxy", "forward", "reverse", "loadbalancer", "lb",
            "haproxy", "nginx", "apache", "iis", "tomcat", "jboss",
            "glassfish", "weblogic", "websphere", "jetty", "netty",
            "wildfly", "payara", "tomee", "resin", "lite",
            "printer", "print", "scan", "scanner", "fax", "faxes",
            "switch", "router", "gateway", "firewall", "fw",
            "security", "camera", "cam", "cameras", "surveillance",
            "cctv", "nvr", "dvr", "voip", "phone", "phones",
            "pbx", "sip", "asterisk", "freeswitch", "sbc",
            "radius", "ldap", "ad", "active-directory", "sso",
            "oauth", "saml", "openid", "cas", "shibboleth",
            "pay", "payment", "payments", "billing", "invoice",
            "invoices", "order", "orders", "cart", "carts",
            "checkout", "shopping", "store", "stores", "market",
            "marketplace", "shop", "catalog", "catalogue", "product",
            "products", "item", "items", "listing", "listings",
            "classified", "classifieds", "ad", "ads", "advert",
            "adsense", "analytics", "track", "tracking", "stats",
            "statistics", "counter", "hit", "hits", "visitor",
            "visitors", "audit", "auditor", "compliance",
            "legal", "terms", "privacy", "policy", "dmca",
            "about", "aboutus", "contact", "contactus", "careers",
            "jobs", "job", "employment", "recruit", "recruitment",
            "hr", "humanresources", "office", "staff", "employee",
            "employees", "intranet", "corp", "corporate",
            "company", "biz", "business", "partner", "partners",
            "vendor", "vendors", "supplier", "suppliers",
            "reseller", "resellers", "affiliate", "affiliates",
            "api", "apis", "developer", "developers", "devhub",
            "sandbox", "sandboxes", "lab", "labs", "research",
            "rnd", "innovation", "prototype", "prototypes",
            "alpha", "beta", "gamma", "release", "releases",
            "version", "versions", "v1", "v2", "v3", "v4", "v5",
            "old", "new", "current", "previous", "legacy",
            "main", "master", "production", "prod", "live",
            "dashboard", "admin", "administrator", "manage",
            "management", "manager", "control", "panel", "cpanel",
            "whm", "plesk", "directadmin", "vesta", "horde",
            "roundcube", "squirrelmail", "rainloop", "afterlogic",
            "phpmyadmin", "phpadmin", "adminer", "phppgadmin",
            "mysql", "pma", "webmin", "usermin", "virtualmin",
            "config", "configure", "configuration", "setup",
            "install", "installer", "update", "updater", "upgrade",
            "migration", "migrate", "backup", "restore",
            "recovery", "failover", "disaster", "dr", "bcp",
            "monitor", "monitoring", "nagios", "zabbix", "prometheus",
            "alert", "alerts", "alarm", "alarms", "warning",
            "warn", "error", "errors", "exception", "exceptions",
            "log", "logs", "logging", "syslog", "rsyslog",
            "syslog-ng", "journal", "journald", "auditd",
            "kibana", "elasticsearch", "logstash", "elk",
            "splunk", "sumologic", "papertrail", "loggly",
            "graylog", "fluentd", "fluentbit", "vector"
        ]

        tasks = []
        semaphore = asyncio.Semaphore(50)
        for sub in subdomains:
            tasks.append(self._check_subdomain(domain, sub, semaphore))

        results = await asyncio.gather(*tasks)
        for r in results:
            if r:
                found.add(r)

        http_tasks = []
        for sub in list(found):
            http_tasks.append(self._verify_http(sub, domain))

        verified = await asyncio.gather(*http_tasks)
        valid = [v for v in verified if v]

        self.logger.info(f"Found {len(valid)} valid subdomains for {domain}")
        return valid

    async def _check_subdomain(self, domain: str, subdomain: str, semaphore) -> Optional[str]:
        async with semaphore:
            try:
                full_domain = f"{subdomain}.{domain}"
                resolver = dns.resolver.Resolver()
                resolver.timeout = 3
                resolver.lifetime = 3
                answers = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: resolver.resolve(full_domain, 'A')
                )
                if answers:
                    return full_domain
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers, dns.exception.Timeout,
                    asyncio.TimeoutError, Exception):
                pass
            return None

    async def _verify_http(self, subdomain: str, domain: str) -> Optional[str]:
        try:
            for scheme in ["https", "http"]:
                url = f"{scheme}://{subdomain}"
                response = await self.requester.get(url, timeout=5)
                if response and response.status < 500:
                    return url
        except Exception:
            pass
        return None
