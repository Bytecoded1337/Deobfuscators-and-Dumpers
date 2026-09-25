from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .compare import write_compare
from .decoder import find_encoded_blob, unpack_outer
from .dump import load_opcode_map, write_dumps
from .format import parse_serialized
from .recover import write_recovered


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def analyze(input_path: Path, out_dir: Path, opcode_map_path: Path | None = None, against: Path | None = None) -> dict[str, Any]:
    source = input_path.read_text("utf-8", errors="replace")
    encoded = find_encoded_blob(source)
    serialized = unpack_outer(encoded)
    root = parse_serialized(serialized)
    opcode_map = load_opcode_map(opcode_map_path)
    summary = write_dumps(out_dir, serialized, root, opcode_map)
    recovered_path = out_dir / "recovered.lua"
    write_recovered(recovered_path, root, opcode_map)
    compare = write_compare(out_dir, out_dir / "constants.json", recovered_path, against)
    manifest = {
        "input": str(input_path),
        "input_sha256": sha256_bytes(input_path.read_bytes()),
        "encoded_chars": len(encoded),
        "serialized_sha256": sha256_bytes(serialized),
        "summary": summary,
        "comparison": {
            "coverage_percent": compare["coverage_percent"],
            "missing_occurrences": compare["missing_occurrences"],
            "extra_occurrences": compare["extra_occurrences"],
            "against_original": bool(against),
        },
        "artifacts": [
            "serialized.bin", "summary.json", "prototypes.json", "constants.json", "constants.txt",
            "constants.csv", "strings.txt", "string_index.json", "opcodes.csv", "opcode_frequency.csv",
            "unknown_opcodes.txt", "ir.txt", "recovered.lua", "compare.json", "compare.txt"
        ],
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), "utf-8")
    return manifest
