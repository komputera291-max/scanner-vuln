"""
Payload Encoder Engine — 20+ encoding methods
Author: ARIF
"""

import base64
import random
import re
import logging
from typing import List, Dict
from urllib.parse import quote, unquote


class PayloadEncoder:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config

    def encode_all(self, payload: str, module: str = "") -> List[str]:
        encoded = []
        encoding_methods = [
            self.url_encode,
            self.double_url_encode,
            self.hex_encode,
            self.unicode_encode,
            self.base64_encode,
            self.html_entity_encode,
            self.octal_encode,
            self.binary_encode,
            self.char_code_encode,
            self.mixed_case,
            self.unicode_normalize,
            self.tab_to_space,
            self.newline_injection,
            self.null_byte_injection,
            self.backslash_escape,
            self.double_quote_wrap,
            self.single_quote_wrap,
            self.space_to_comment,
            self.space_to_plus,
            self.utf16_encode,
            self.escape_sequence_encode,
        ]
        for method in encoding_methods:
            try:
                result = method(payload)
                if result and result != payload:
                    if isinstance(result, list):
                        encoded.extend(result[:3])
                    else:
                        encoded.append(result)
            except Exception as e:
                self.logger.debug(f"Encoding error ({method.__name__}): {e}")
        if module == "sql" or module == "sqli":
            encoded.extend(self._sql_specific_encodings(payload))
        if module == "xss":
            encoded.extend(self._xss_specific_encodings(payload))
        return encoded[:50]

    def url_encode(self, payload: str) -> str:
        result = ""
        for char in payload:
            if char in " <>#%\"{}|\\^~[]`;@$!()*+,=-":
                result += quote(char, safe='')
            elif char == '/':
                result += '%2F'
            elif char == '.':
                result += '%2E'
            else:
                result += char
        return result

    def double_url_encode(self, payload: str) -> str:
        once = self.url_encode(payload)
        return self.url_encode(once)

    def hex_encode(self, payload: str) -> str:
        return ''.join(f'\\x{ord(c):02x}' for c in payload)

    def unicode_encode(self, payload: str) -> str:
        return ''.join(f'\\u{ord(c):04x}' for c in payload)

    def base64_encode(self, payload: str) -> str:
        try:
            return base64.b64encode(payload.encode()).decode()
        except Exception:
            return payload

    def html_entity_encode(self, payload: str) -> str:
        result = ""
        for char in payload:
            if ord(char) > 127 or char in "<>&\"'":
                result += f'&#{ord(char)};'
            else:
                result += char
        return result

    def octal_encode(self, payload: str) -> str:
        return ''.join(f'\\{oct(ord(c))[2:].zfill(3)}' for c in payload)

    def binary_encode(self, payload: str) -> str:
        return ' '.join(format(ord(c), '08b') for c in payload)

    def char_code_encode(self, payload: str) -> str:
        codes = [str(ord(c)) for c in payload]
        return 'String.fromCharCode(' + ','.join(codes) + ')'

    def mixed_case(self, payload: str) -> List[str]:
        variations = []
        if len(payload) > 3:
            upper_variants = []
            for i, c in enumerate(payload):
                if c.isalpha():
                    for v in [c.upper(), c.lower()]:
                        variant = payload[:i] + v + payload[i+1:]
                        if variant != payload:
                            upper_variants.append(variant)
            if upper_variants:
                variations.extend(random.sample(upper_variants, min(3, len(upper_variants))))
            alt_case = ''.join(
                c.upper() if i % 2 == 0 else c.lower()
                for i, c in enumerate(payload)
            )
            if alt_case != payload:
                variations.append(alt_case)
            all_upper = payload.upper()
            if all_upper != payload:
                variations.append(all_upper)
            all_lower = payload.lower()
            if all_lower != payload:
                variations.append(all_lower)
        return variations

    def unicode_normalize(self, payload: str) -> str:
        replacements = {
            'a': '\u0430', 'e': '\u0435', 'o': '\u043e', 'p': '\u0440',
            'c': '\u0441', 'y': '\u0443', 'x': '\u0445', 'i': '\u0456',
            'A': '\u0410', 'E': '\u0415', 'O': '\u041e', 'P': '\u0420',
            'C': '\u0421', 'Y': '\u0423', 'X': '\u0425', 'I': '\u0406',
            'B': '\u0412', 'H': '\u041d', 'K': '\u041a', 'M': '\u041c',
            'T': '\u0422', '<': '\u2039', '>': '\u203a'
        }
        result = ''.join(replacements.get(c, c) for c in payload)
        return result if result != payload else payload

    def tab_to_space(self, payload: str) -> str:
        return payload.replace(' ', '\t')

    def newline_injection(self, payload: str) -> str:
        if ' ' in payload:
            return payload.replace(' ', '%0A')
        return payload

    def null_byte_injection(self, payload: str) -> str:
        return payload + '%00'

    def backslash_escape(self, payload: str) -> str:
        escaped = payload.replace("'", "\\'").replace('"', '\\"')
        escaped = escaped.replace("\n", "\\n").replace("\t", "\\t")
        return escaped

    def double_quote_wrap(self, payload: str) -> str:
        if '"' not in payload:
            return '"' + payload + '"'
        return payload

    def single_quote_wrap(self, payload: str) -> str:
        if "'" not in payload:
            return "'" + payload + "'"
        return payload

    def space_to_comment(self, payload: str) -> str:
        if ' ' in payload:
            return payload.replace(' ', '/**/')
        return payload

    def space_to_plus(self, payload: str) -> str:
        if ' ' in payload:
            return payload.replace(' ', '+')
        return payload

    def utf16_encode(self, payload: str) -> str:
        result = ''
        for c in payload:
            code = ord(c)
            result += f'%u{code:04X}'
        return result

    def escape_sequence_encode(self, payload: str) -> str:
        result = ''
        for c in payload:
            if c.isalnum():
                result += f'\\x{ord(c):02x}'
            else:
                result += c
        return result

    def _sql_specific_encodings(self, payload: str) -> List[str]:
        variants = []
        variants.append(payload.replace("'", "\\'"))
        variants.append(payload.replace("'", "''"))
        variants.append(payload.replace(" ", "/**/"))
        variants.append(payload.replace(" ", "%20"))
        if "1=1" in payload:
            variants.append(payload.replace("1=1", "2=2"))
            variants.append(payload.replace("1=1", "'a'='a'"))
            variants.append(payload.replace("1=1", "'1'='1'"))
        if "OR" in payload.upper():
            variants.append(payload.replace("OR", "||"))
            variants.append(payload.replace("OR", "O/**/R"))
        if "AND" in payload.upper():
            variants.append(payload.replace("AND", "&&"))
            variants.append(payload.replace("AND", "A/**/ND"))
        if "SELECT" in payload.upper():
            variants.append(payload.replace("SELECT", "SEL/**/ECT"))
            variants.append(payload.replace("SELECT", "SELeCT"))
        if "UNION" in payload.upper():
            variants.append(payload.replace("UNION", "UN/**/ION"))
            variants.append(payload.replace("UNION", "UNION"))
        return variants

    def _xss_specific_encodings(self, payload: str) -> List[str]:
        variants = []
        if "<script>" in payload.lower():
            variants.append(payload.replace("<script>", "<sCRiPt>"))
            variants.append(payload.replace("<script>", "<SCR%49PT>"))
            variants.append(payload.replace("<script>", "<%73cript>"))
        if "alert(" in payload.lower():
            variants.append(payload.replace("alert(", "alert&#40;"))
            variants.append(payload.replace("alert(", "alert%28"))
            variants.append(payload.replace("alert(", "alert\\("))
        if "onerror" in payload.lower():
            variants.append(payload.replace("onerror", "onError"))
            variants.append(payload.replace("onerror", "on%e"))
        if "onload" in payload.lower():
            variants.append(payload.replace("onload", "onLoad"))
            variants.append(payload.replace("onload", "on%6c%6f%61%64"))
        return variants
