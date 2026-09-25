from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .compare import write_compare
from .decoder import find_encoded_blob, unpack_outer
from .decompiler import run_external_decompiler
from .dump import load_opcode_map, write_dumps
from .format import parse_serialized
from .pipeline import analyze
from .recover import write_recovered
from .rename import semantic_rename_lua


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ib1", description="IronBrew1 decoder, dumper, analysis recovery CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("all", help="decode + parse + dump + recover + compare")
    a.add_argument("input", type=Path)
    a.add_argument("-o", "--out", type=Path, default=Path("ib1_out"))
    a.add_argument("--opcode-map", type=Path)
    a.add_argument("--against", type=Path, help="optional original/pre-obfuscation Lua source for literal comparison")

    u = sub.add_parser("unpack", help="decode the outer payload into serialized.bin")
    u.add_argument("input", type=Path)
    u.add_argument("-o", "--output", type=Path, default=Path("serialized.bin"))

    d = sub.add_parser("dump", help="parse serialized.bin and emit constants/IR files")
    d.add_argument("serialized", type=Path)
    d.add_argument("-o", "--out", type=Path, default=Path("ib1_out"))
    d.add_argument("--opcode-map", type=Path)

    r = sub.add_parser("recover", help="emit conservative valid-Lua analysis representation")
    r.add_argument("serialized", type=Path)
    r.add_argument("-o", "--output", type=Path, default=Path("recovered.lua"))
    r.add_argument("--opcode-map", type=Path)

    c = sub.add_parser("compare", help="compare dumped constants with recovered.lua")
    c.add_argument("constants", type=Path)
    c.add_argument("recovered", type=Path)
    c.add_argument("-o", "--out", type=Path, default=Path("ib1_compare"))
    c.add_argument("--against", type=Path)

    n = sub.add_parser("rename", help="semantic Roblox local-variable renamer")
    n.add_argument("input", type=Path)
    n.add_argument("-o", "--output", type=Path, default=Path("renamed.lua"))
    n.add_argument("--map-output", type=Path)

    e = sub.add_parser("decompile-external", help="run an external decompiler on reconstructed standard Lua/Luau bytecode")
    e.add_argument("bytecode", type=Path)
    e.add_argument("--exe", type=Path, required=True, help="decompiler executable")
    e.add_argument("--arg", action="append", default=[], help="extra argument passed before the bytecode path; repeat as needed")
    e.add_argument("-o", "--output", type=Path, default=Path("decompiled.lua"))
    return p


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.cmd == "all":
            result = analyze(args.input, args.out, args.opcode_map, args.against)
            print(json.dumps(result, indent=2))
        elif args.cmd == "unpack":
            src = args.input.read_text("utf-8", errors="replace")
            data = unpack_outer(find_encoded_blob(src))
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(data)
            print(f"[+] wrote {len(data)} bytes -> {args.output}")
        elif args.cmd == "dump":
            data = args.serialized.read_bytes()
            root = parse_serialized(data)
            summary = write_dumps(args.out, data, root, load_opcode_map(args.opcode_map))
            print(json.dumps(summary, indent=2))
        elif args.cmd == "recover":
            root = parse_serialized(args.serialized.read_bytes())
            write_recovered(args.output, root, load_opcode_map(args.opcode_map))
            print(f"[+] wrote {args.output}")
        elif args.cmd == "compare":
            result = write_compare(args.out, args.constants, args.recovered, args.against)
            print(json.dumps(result, indent=2, ensure_ascii=False))
        elif args.cmd == "rename":
            src = args.input.read_text("utf-8", errors="replace")
            renamed, mapping = semantic_rename_lua(src)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(renamed, "utf-8")
            map_path = args.map_output or args.output.with_suffix(".renames.json")
            map_path.write_text(json.dumps(mapping, indent=2), "utf-8")
            print(f"[+] wrote {args.output} ({len(mapping)} renames)")
        elif args.cmd == "decompile-external":
            output = run_external_decompiler(args.bytecode, args.exe, args.arg)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, "utf-8")
            print(f"[+] wrote {args.output}")
        return 0
    except Exception as exc:
        print(f"[-] {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
