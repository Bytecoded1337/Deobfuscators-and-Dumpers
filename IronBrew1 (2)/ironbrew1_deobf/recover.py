from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .format import flatten_prototypes


def lua_literal(value: Any) -> str:
    if value is None:
        return "nil"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, float):
        if value != value:
            return "(0/0)"
        if value == float("inf"):
            return "(1/0)"
        if value == float("-inf"):
            return "(-1/0)"
    return repr(value)


def table_value(value: Any) -> str:
    if isinstance(value, list):
        return "{" + ", ".join(lua_literal(x) for x in value) + "}"
    return lua_literal(value)


def render_recovered(root: dict[str, Any], opcode_map: dict[int, str] | None = None) -> str:
    """Emit valid Lua analysis-source without inventing unresolved VM semantics."""
    opcode_map = opcode_map or {}
    prototypes = flatten_prototypes(root)
    lines: list[str] = [
        "-- IronBrew1 recovered analysis source",
        "-- IMPORTANT: unresolved virtual opcodes are preserved as __ib1_op calls.",
        "-- This file is an analysis representation, not a claim of exact original source.",
        "",
        "local function __ib1_op(opcode, pc, A, B, C, D, mode, flags)",
        "    return {opcode=opcode, pc=pc, A=A, B=B, C=C, D=D, mode=mode, flags=flags}",
        "end",
        "",
    ]
    for proto in reversed(prototypes):
        pid = proto["id"]
        params = ", ".join(f"arg{i}" for i in range(1, int(proto["num_params"]) + 1))
        lines.append(f"local function proto_{pid}({params})")
        lines.append("    local K = {")
        for i, item in enumerate(proto["constants"]):
            lines.append(f"        [{i}] = {lua_literal(item['value'])}, -- {item['kind']}")
        lines.append("    }")
        if proto["children"]:
            child_ids = [str(child.get("id")) for child in proto["children"]]
            lines.append(f"    -- child prototypes: {', '.join(child_ids)}")
        lines.append("    local ir = {}")
        for ins in proto["instructions"]:
            mapped = opcode_map.get(ins["opcode"])
            flag_bits = (1 if ins["flag"] else 0) | (2 if ins["flag_b"] else 0) | (4 if ins["flag_c"] else 0)
            vals = [table_value(ins.get(key)) for key in ("A", "B", "C", "D")]
            suffix = f" -- {mapped}" if mapped else ""
            lines.append(
                f"    ir[{ins['pc']}] = __ib1_op({ins['opcode']}, {ins['pc']}, {vals[0]}, {vals[1]}, {vals[2]}, {vals[3]}, {ins['mode']}, {flag_bits}){suffix}"
            )
        lines.append("    return {constants = K, ir = ir}")
        lines.append("end")
        lines.append("")
    lines.append("return proto_0(...)")
    return "\n".join(lines) + "\n"


def write_recovered(path: Path, root: dict[str, Any], opcode_map: dict[int, str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_recovered(root, opcode_map), encoding="utf-8")
