Mutation rules are defined in the payloads/engine/mutator.py
The mutation engine generates variations dynamically:
- Case mutation (upper/lower/mixed)
- Whitespace variation (tab, newline, null byte)
- Comment injection (SQL, XSS context)
- Operator swap (OR -> ||, AND -> &&)
- Quote alternation (' vs " vs `)
- Parenthesis variation
- Null byte append
- Double encoding
- Unicode bypass
- Base64 wrapping
- eval() wrapping
- Concatenation bypass
- Keyword splitting
- Encoding nesting
- Boundary injection

Each seed payload can generate 40+ mutation variants.
With encoding engine, 15+ encoding methods are applied on top.
Total combinations reach millions per module.
