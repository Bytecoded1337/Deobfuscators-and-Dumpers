from __future__ import annotations

import csv
import json
import math
from collections import Counter
from pathlib import Path
from typing import Any

from .format import flatten_prototypes


def json_value(value: Any) -> Any:
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        return repr(value)
    return value


def constant_text(value: Any) -> str:
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "nil"
    return repr(value)


def load_opcode_map(path: Path | None) -> dict[int, str]:
    if path is None:
        return {}
    raw = json.loads(path.read_text("utf-8"))
    return {int(k): str(v) for k, v in raw.items()}


def build_analysis(serialized: bytes, root: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    prototypes = flatten_prototypes(root)
    constants: list[dict[str, Any]] = []
    for proto in prototypes:
        pid = proto["id"]
        for index, item in enumerate(proto["constants"]):
            constants.append({
                "prototype": pid,
                "index": index,
                "kind": item["kind"],
                "tag": item["tag"],
                "subtype": item["subtype"],
                "value": json_value(item["value"]),
            })
    opcode_counts = Counter(ins["opcode"] for proto in prototypes for ins in proto["instructions"])
    summary = {
        "serialized_bytes": len(serialized),
        "prototypes": len(prototypes),
        "constants": len(constants),
        "strings": sum(1 for x in constants if x["kind"] == "string"),
        "instructions": sum(len(proto["instructions"]) for proto in prototypes),
        "unique_opcodes": len(opcode_counts),
        "opcode_frequency": {str(k): v for k, v in sorted(opcode_counts.items())},
        "instruction_layout": {
            "opcode_key": 13,
            "A_key": 6,
            "B_key": 3,
            "C_key": 1,
            "D_aux_key": 9,
        },
    }
    return prototypes, constants, summary


def write_dumps(out_dir: Path, serialized: bytes, root: dict[str, Any], opcode_map: dict[int, str] | None = None) -> dict[str, Any]:
    opcode_map = opcode_map or {}
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "serialized.bin").write_bytes(serialized)
    prototypes, constants, summary = build_analysis(serialized, root)

    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2), "utf-8")
    (out_dir / "constants.json").write_text(json.dumps(constants, indent=2, ensure_ascii=False), "utf-8")

    constants_lines: list[str] = []
    strings_lines: list[str] = []
    for proto in prototypes:
        constants_lines.append(f"\n== prototype {proto['id']} depth={proto['depth']} constants={len(proto['constants'])} ==")
        for index, item in enumerate(proto["constants"]):
            value = json_value(item["value"])
            constants_lines.append(f"K{index:04d} {item['kind']:<8} {constant_text(value)}")
            if item["kind"] == "string":
                strings_lines.append(f"P{proto['id']}:K{index} {value}")
    (out_dir / "constants.txt").write_text("\n".join(constants_lines) + "\n", "utf-8")
    (out_dir / "strings.txt").write_text("\n".join(strings_lines) + "\n", "utf-8")

    string_index: dict[str, list[dict[str, int]]] = {}
    for item in constants:
        if item["kind"] == "string":
            string_index.setdefault(str(item["value"]), []).append({"prototype": item["prototype"], "index": item["index"]})
    (out_dir / "string_index.json").write_text(json.dumps(string_index, indent=2, ensure_ascii=False), "utf-8")

    with (out_dir / "constants.csv").open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=["prototype", "index", "kind", "tag", "subtype", "value"])
        w.writeheader()
        w.writerows(constants)

    proto_meta = []
    ir_lines: list[str] = []
    opcode_rows: list[dict[str, Any]] = []
    for proto in prototypes:
        pid = proto["id"]
        proto_meta.append({
            "id": pid,
            "depth": proto["depth"],
            "start": proto["start"],
            "end": proto["end"],
            "frame_size": proto["frame_size"],
            "num_params": proto["num_params"],
            "prototype_flag": proto["prototype_flag"],
            "field_permutation": proto["field_permutation"],
            "constants": len(proto["constants"]),
            "instructions": len(proto["instructions"]),
            "children": [child.get("id") for child in proto["children"]],
        })
        ir_lines.append(
            f"\n== prototype {pid} depth={proto['depth']} params={proto['num_params']} "
            f"frame={proto['frame_size']} ins={len(proto['instructions'])} =="
        )
        ir_lines.append(f"field_permutation={proto['field_permutation']}")
        for ins in proto["instructions"]:
            opname = opcode_map.get(ins["opcode"], f"OP_{ins['opcode']:03d}")
            ir_lines.append(
                f"{ins['pc']:05d} {opname:<18} A={ins['A']!r} B={ins['B']!r} C={ins['C']!r} D={ins['D']!r} "
                f"mode={ins['mode']} flags={int(ins['flag'])}{int(ins['flag_b'])}{int(ins['flag_c'])}"
            )
            opcode_rows.append({"prototype": pid, "pc": ins["pc"], "opcode": ins["opcode"], "name": opname,
                                "A": repr(ins["A"]), "B": repr(ins["B"]), "C": repr(ins["C"]), "D": repr(ins["D"]),
                                "mode": ins["mode"], "flag": ins["flag"], "flag_b": ins["flag_b"], "flag_c": ins["flag_c"]})
    (out_dir / "prototypes.json").write_text(json.dumps(proto_meta, indent=2), "utf-8")
    with (out_dir / "opcode_frequency.csv").open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["opcode", "name", "count"])
        for opcode, count in sorted(Counter(ins["opcode"] for proto in prototypes for ins in proto["instructions"]).items()):
            w.writerow([opcode, opcode_map.get(opcode, f"OP_{opcode:03d}"), count])
    (out_dir / "unknown_opcodes.txt").write_text("\n".join(
        f"{opcode}\t{count}" for opcode, count in sorted(Counter(ins["opcode"] for proto in prototypes for ins in proto["instructions"]).items()) if opcode not in opcode_map
    ) + "\n", "utf-8")
    (out_dir / "ir.txt").write_text("\n".join(ir_lines) + "\n", "utf-8")
    with (out_dir / "opcodes.csv").open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=list(opcode_rows[0].keys()) if opcode_rows else ["prototype", "pc", "opcode"])
        w.writeheader()
        w.writerows(opcode_rows)
    return summary
