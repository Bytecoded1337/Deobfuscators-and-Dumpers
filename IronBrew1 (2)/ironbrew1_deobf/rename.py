from __future__ import annotations

import re


def lower_camel(name: str) -> str:
    if not name:
        return "value"
    initialisms = {"UI": "ui", "GUI": "gui", "HTTP": "http", "JSON": "json"}
    for prefix, repl in initialisms.items():
        if name.startswith(prefix):
            return repl + name[len(prefix):]
    if name.isupper():
        return name.lower()
    return name[0].lower() + name[1:]


def discover_semantic_names(source: str) -> dict[str, str]:
    candidates: list[tuple[str, str]] = []
    patterns = [
        (r"\blocal\s+([A-Za-z_]\w*)\s*=\s*Instance\s*\.\s*new\(\s*['\"]([^'\"]+)['\"]\s*\)", 2),
        (r"\blocal\s+([A-Za-z_]\w*)\s*=\s*game\s*:\s*GetService\(\s*['\"]([^'\"]+)['\"]\s*\)", 2),
        (r"\blocal\s+([A-Za-z_]\w*)\s*=\s*[^\n;]+:\s*(?:WaitForChild|FindFirstChild)\(\s*['\"]([^'\"]+)['\"]\s*\)", 2),
        (r"\blocal\s+([A-Za-z_]\w*)\s*=\s*[^\n;]+\.LocalPlayer\b", None),
        (r"\blocal\s+([A-Za-z_]\w*)\s*=\s*[^\n;]+\.Character\b", None),
    ]
    for pattern, group in patterns:
        for m in re.finditer(pattern, source, re.I):
            if group is None:
                rhs_name = "localPlayer" if "LocalPlayer" in m.group(0) else "character"
            else:
                rhs_name = lower_camel(m.group(group))
            candidates.append((m.group(1), rhs_name))
    existing = set(re.findall(r"\blocal\s+([A-Za-z_]\w*)", source))
    reserved = set(existing)
    mapping: dict[str, str] = {}
    for old, base in candidates:
        if old in mapping or old == base:
            continue
        new = base
        suffix = 2
        while new in reserved and new != old:
            new = f"{base}{suffix}"
            suffix += 1
        mapping[old] = new
        reserved.add(new)
    return mapping


def replace_identifiers_lua(source: str, mapping: dict[str, str]) -> str:
    if not mapping:
        return source
    out: list[str] = []
    i = 0
    n = len(source)
    while i < n:
        if source.startswith("--", i):
            if i + 2 < n and source[i + 2] == "[":
                m = re.match(r"--\[(=*)\[", source[i:])
                if m:
                    close = "]" + m.group(1) + "]"
                    j = source.find(close, i + len(m.group(0)))
                    j = n if j < 0 else j + len(close)
                    out.append(source[i:j]); i = j; continue
            j = source.find("\n", i)
            j = n if j < 0 else j + 1
            out.append(source[i:j]); i = j; continue
        if source[i] in "'\"":
            quote = source[i]; j = i + 1
            while j < n:
                if source[j] == "\\": j += 2; continue
                if source[j] == quote: j += 1; break
                j += 1
            out.append(source[i:j]); i = j; continue
        if source[i] == "[":
            m = re.match(r"\[(=*)\[", source[i:])
            if m:
                close = "]" + m.group(1) + "]"
                j = source.find(close, i + len(m.group(0)))
                j = n if j < 0 else j + len(close)
                out.append(source[i:j]); i = j; continue
        if source[i].isalpha() or source[i] == "_":
            j = i + 1
            while j < n and (source[j].isalnum() or source[j] == "_"): j += 1
            token = source[i:j]
            out.append(mapping.get(token, token)); i = j; continue
        out.append(source[i]); i += 1
    return "".join(out)


def semantic_rename_lua(source: str) -> tuple[str, dict[str, str]]:
    mapping = discover_semantic_names(source)
    return replace_identifiers_lua(source, mapping), mapping
