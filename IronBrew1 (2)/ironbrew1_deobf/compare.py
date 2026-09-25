from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


def _decode_lua_quoted(body: str) -> str:
    out: list[str] = []
    i = 0
    escapes = {"a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v", "\\": "\\", '"': '"', "'": "'"}
    while i < len(body):
        if body[i] != "\\":
            out.append(body[i]); i += 1; continue
        i += 1
        if i >= len(body):
            out.append("\\"); break
        c = body[i]
        if c in escapes:
            out.append(escapes[c]); i += 1
        elif c == "x" and i + 2 < len(body) and re.fullmatch(r"[0-9A-Fa-f]{2}", body[i+1:i+3]):
            out.append(chr(int(body[i+1:i+3], 16))); i += 3
        elif c.isdigit():
            m = re.match(r"\d{1,3}", body[i:])
            out.append(chr(int(m.group(0)) % 256)); i += len(m.group(0))
        elif c == "z":
            i += 1
            while i < len(body) and body[i].isspace(): i += 1
        else:
            out.append(c); i += 1
    return "".join(out)


def extract_lua_strings(source: str) -> list[str]:
    values: list[str] = []
    i = 0
    n = len(source)
    while i < n:
        if source.startswith("--", i):
            j = source.find("\n", i)
            i = n if j < 0 else j + 1
            continue
        if source[i] in "'\"":
            quote = source[i]; j = i + 1; body: list[str] = []
            while j < n:
                if source[j] == "\\" and j + 1 < n:
                    body.extend([source[j], source[j+1]]); j += 2; continue
                if source[j] == quote: break
                body.append(source[j]); j += 1
            values.append(_decode_lua_quoted("".join(body)))
            i = min(n, j + 1); continue
        if source[i] == "[":
            m = re.match(r"\[(=*)\[", source[i:])
            if m:
                close = "]" + m.group(1) + "]"
                start = i + len(m.group(0))
                j = source.find(close, start)
                if j >= 0:
                    values.append(source[start:j]); i = j + len(close); continue
        i += 1
    return values


def compare_constants(constants: list[dict[str, Any]], recovered_source: str, against_source: str | None = None) -> dict[str, Any]:
    dumped_strings = [str(x["value"]) for x in constants if x.get("kind") == "string"]
    recovered_strings = extract_lua_strings(recovered_source)
    dumped = Counter(dumped_strings)
    recovered = Counter(recovered_strings)
    matched = dumped & recovered
    missing = dumped - recovered
    extra = recovered - dumped
    result: dict[str, Any] = {
        "dumped_string_constants": sum(dumped.values()),
        "dumped_unique_strings": len(dumped),
        "recovered_string_literals": sum(recovered.values()),
        "recovered_unique_strings": len(recovered),
        "matched_occurrences": sum(matched.values()),
        "missing_occurrences": sum(missing.values()),
        "extra_occurrences": sum(extra.values()),
        "coverage_percent": round((sum(matched.values()) / max(1, sum(dumped.values()))) * 100, 2),
        "missing": [{"value": k, "count": v} for k, v in missing.most_common()],
        "extra": [{"value": k, "count": v} for k, v in extra.most_common()],
    }
    if against_source is not None:
        original = Counter(extract_lua_strings(against_source))
        overlap = dumped & original
        absent_from_dump = original - dumped
        not_in_original = dumped - original
        result["against_original"] = {
            "original_string_literals": sum(original.values()),
            "original_unique_strings": len(original),
            "dumped_vs_original_matched_occurrences": sum(overlap.values()),
            "original_missing_from_dump": [{"value": k, "count": v} for k, v in absent_from_dump.most_common()],
            "dumped_not_in_original": [{"value": k, "count": v} for k, v in not_in_original.most_common()],
        }
    return result


def write_compare(out_dir: Path, constants_path: Path, recovered_path: Path, against_path: Path | None = None) -> dict[str, Any]:
    constants = json.loads(constants_path.read_text("utf-8"))
    recovered = recovered_path.read_text("utf-8", errors="replace")
    against = against_path.read_text("utf-8", errors="replace") if against_path else None
    result = compare_constants(constants, recovered, against)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "compare.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), "utf-8")
    lines = [
        "IronBrew1 constants vs recovered.lua",
        "=====================================",
        f"dumped string constants : {result['dumped_string_constants']}",
        f"recovered string literals: {result['recovered_string_literals']}",
        f"matched occurrences      : {result['matched_occurrences']}",
        f"missing occurrences      : {result['missing_occurrences']}",
        f"extra occurrences        : {result['extra_occurrences']}",
        f"representation coverage  : {result['coverage_percent']}%",
        "",
        "NOTE: representation coverage only checks literal presence. It does NOT prove opcode/semantic recovery.",
    ]
    if result["missing"]:
        lines += ["", "Missing from recovered.lua:"] + [f"  x{x['count']} {x['value']!r}" for x in result["missing"][:100]]
    if result.get("against_original"):
        a = result["against_original"]
        lines += [
            "", "Dumped constants vs supplied original source:",
            f"  original string literals              : {a['original_string_literals']}",
            f"  matched dumped/original occurrences   : {a['dumped_vs_original_matched_occurrences']}",
            f"  original literals missing from dump   : {sum(x['count'] for x in a['original_missing_from_dump'])}",
            f"  dumped literals not in original       : {sum(x['count'] for x in a['dumped_not_in_original'])}",
        ]
    (out_dir / "compare.txt").write_text("\n".join(lines) + "\n", "utf-8")
    return result
