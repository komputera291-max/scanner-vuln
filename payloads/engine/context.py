"""
Context Adaptor — Adapts payloads for different contexts
Author: ARIF
"""

import logging
from typing import List, Dict


class ContextAdaptor:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config

    def adapt(self, payloads: List[str], module: str) -> List[str]:
        adapted = list(payloads)
        for payload in payloads[:50]:
            adapted.extend(self._html_context(payload, module))
            adapted.extend(self._js_context(payload, module))
            adapted.extend(self._attribute_context(payload, module))
            adapted.extend(self._url_context(payload, module))
            adapted.extend(self._json_context(payload, module))
        return list(set(adapted))

    def _html_context(self, payload: str, module: str) -> List[str]:
        contexts = []
        if module == "xss":
            contexts.append(f"{payload}")
            contexts.append(f"<tag>{payload}</tag>")
            contexts.append(f"<div>{payload}</div>")
        return contexts

    def _js_context(self, payload: str, module: str) -> List[str]:
        contexts = []
        if module == "xss":
            contexts.append(f"'{payload}'")
            contexts.append(f"\"{payload}\"")
            contexts.append(f"`{payload}`")
            contexts.append(f";{payload};")
            contexts.append(f"({payload})")
            contexts.append(f"1+{payload}+1")
        return contexts

    def _attribute_context(self, payload: str, module: str) -> List[str]:
        contexts = []
        if module == "xss":
            contexts.append(f'"{payload}"')
            contexts.append(f"'{payload}'")
            contexts.append(f'value="{payload}"')
            contexts.append(f' href="{payload}"')
            contexts.append(f' src="{payload}"')
        elif module in ["sql", "sqli"]:
            contexts.append(payload)
            contexts.append(f'"{payload}"')
            contexts.append(f"'{payload}'")
            contexts.append(f"({payload})")
        return contexts

    def _url_context(self, payload: str, module: str) -> List[str]:
        contexts = []
        if module == "xss":
            contexts.append(f"javascript:{payload}")
            contexts.append(f"javascript:void({payload})")
        if module == "redirect":
            contexts.append(f"//{payload}")
            contexts.append(f"https://{payload}")
            contexts.append(f"http://{payload}")
        return contexts

    def _json_context(self, payload: str, module: str) -> List[str]:
        contexts = []
        if module == "xss":
            contexts.append(f'{{"key": "{payload}"}}')
        if module == "sqli":
            contexts.append(f'{{"key": "{payload}"}}')
        return contexts
