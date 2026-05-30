"""
Payload Combinator — Chaining encoder + mutator for cross-variations
Author: ARIF
"""

import random
import logging
from typing import List, Dict
from payloads.engine.encoder import PayloadEncoder
from payloads.engine.mutator import PayloadMutator


class PayloadCombinator:
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.encoder = PayloadEncoder(config)
        self.mutator = PayloadMutator(config)

    def combine(self, payload: str, module: str = "", depth: int = 2) -> List[str]:
        combined = set()
        if depth < 1:
            return [payload]
        mutations = self.mutator.mutate(payload, module)[:10]
        for mutation in mutations:
            combined.add(mutation)
            encodings = self.encoder.encode_all(mutation, module)[:5]
            for enc in encodings:
                combined.add(enc)
        encodings = self.encoder.encode_all(payload, module)[:10]
        for enc in encodings:
            combined.add(enc)
            mutations2 = self.mutator.mutate(enc, module)[:5]
            for m2 in mutations2:
                combined.add(m2)
        if depth >= 3:
            for base in list(combined)[:5]:
                combined.update(self.combine(base, module, depth - 1))
        combined.discard(payload)
        return list(combined)[:100]

    def chain_encoding(self, payload: str, module: str = "") -> List[str]:
        chained = []
        current = payload
        for chain_depth in range(5):
            try:
                from urllib.parse import quote, unquote
                encoded = quote(current, safe='')
                chained.append(encoded)
                encoded_double = quote(encoded, safe='')
                chained.append(encoded_double)
                encoded_triple = quote(encoded_double, safe='')
                chained.append(encoded_triple)
            except Exception:
                pass
        return list(set(chained))
