from __future__ import annotations

import argparse
import json
import math
import re
import struct
from collections import Counter
from pathlib import Path
from typing import Any

LEAF = -1


def find_encoded_blob(source: str) -> str:
    candidates = []
    for m in re.finditer(r"\[(=*)\[(.*?)\]\1\]", source, re.S):
        body = m.group(2)
        if len(body) >= 100:
            candidates.append(body)
    if not candidates:
        raise ValueError("no Lua long-bracket payload found")
    candidates.sort(key=len, reverse=True)
    for body in candidates:
        if all(33 <= ord(ch) <= 117 for ch in body):
            return body
    return candidates[0]


def ascii85_ib1(text: str) -> bytes:
    out = bytearray()
    vals = [ord(ch) for ch in text]
    i = 0
    while i < len(vals):
        chunk = vals[i:i + 5]
        n = len(chunk)
        if not n:
            break
        for value in chunk:
            if not 33 <= value < 118:
                raise ValueError(f"invalid Base85 byte 0x{value:02x} at offset {i}")
        if n < 5:
            chunk += [117] * (5 - n)
        value = 0
        for b in chunk:
            value = value * 85 + (b - 33)
        block = bytes(((value >> 24) & 255, (value >> 16) & 255,
                       (value >> 8) & 255, value & 255))
        out += block if n == 5 else block[:n - 1]
        i += 5
    return bytes(out)


class BitReader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.bits_value = 0
        self.bits_count = 0

    def _fill(self, count: int) -> None:
        while self.bits_count < count and self.pos < len(self.data):
            self.bits_value |= self.data[self.pos] << self.bits_count
            self.bits_count += 8
            self.pos += 1

    def bit(self) -> int:
        if self.bits_count == 0:
            self._fill(1)
        if self.bits_count == 0:
            raise EOFError("bitstream ended")
        value = self.bits_value & 1
        self.bits_value >>= 1
        self.bits_count -= 1
        return value

    def bits(self, count: int) -> int:
        if count <= 0:
            return 0
        self._fill(count)
        if self.bits_count < count:
            raise EOFError("bitstream ended")
        mask = (1 << count) - 1
        value = self.bits_value & mask
        self.bits_value >>= count
        self.bits_count -= count
        return value

    def gamma(self) -> int:
        zeroes = 0
        while self.bit() == 0:
            zeroes += 1
            if zeroes > 31:
                break
        if zeroes == 0:
            return 1
        value = 1
        for _ in range(zeroes):
            value = value * 2 + self.bit()
        return value

    def rice(self, width: int) -> int:
        quotient = 0
        while self.bit() == 0:
            quotient += 1
        if width == 0:
            return quotient
        return quotient * (1 << width) + self.bits(width)


def build_huffman_tree(reader: BitReader, direct_symbols: bool) -> dict:
    tree: dict = {}
    count = reader.gamma() - 1
    if count <= 0:
        return tree

    groups: dict[int, list[int]] = {}
    max_width = 0
    last_symbol = -1
    last_width = 0

    for index in range(1, count + 1):
        if direct_symbols:
            symbol = reader.bits(8) if index == 1 else last_symbol + reader.gamma()
        else:
            delta = reader.gamma()
            symbol = delta - 1 if index == 1 else last_symbol + delta

        if index == 1:
            width = reader.gamma()
        else:
            width = last_width if reader.bit() == 1 else reader.gamma()

        groups.setdefault(width, []).append(symbol)
        max_width = max(max_width, width)
        last_symbol = symbol
        last_width = width

    code = 0
    previous_width = 0
    for width in range(1, max_width + 1):
        symbols = groups.get(width)
        if symbols is None:
            continue
        symbols.sort()
        if width > previous_width:
            code <<= width - previous_width
            previous_width = width
        for symbol in symbols:
            node = tree
            for bit_index in range(width - 1, -1, -1):
                bit = (code >> bit_index) & 1
                node = node.setdefault(bit, {})
            node[LEAF] = symbol
            code += 1
    return tree


def decode_huffman_symbol(reader: BitReader, tree: dict) -> int | None:
    node = tree
    while True:
        node = node.get(reader.bit())
        if node is None:
            return None
        if LEAF in node:
            return node[LEAF]


def entropy_decode(data: bytes, state: list[int | None]) -> bytes:
    reader = BitReader(data)
    literal_tree = build_huffman_tree(reader, False)
    after_zero_tree = build_huffman_tree(reader, False)
    after_run_tree = build_huffman_tree(reader, False)
    value_tree = build_huffman_tree(reader, True)
    zero_value_tree = build_huffman_tree(reader, True)

    mode = reader.bits(2)
    if mode == 0:
        p0, p1, p2, p3 = [x or 0 for x in state]
    elif mode == 1:
        delta_map = {0: -1, 1: 0, 2: 1, 3: 2}
        deltas = [delta_map[reader.bits(2)] for _ in range(4)]
        p0 = (state[0] or 0) + deltas[0]
        p1 = (state[1] or 0) + deltas[1]
        p2 = (state[2] or 0) + deltas[2]
        p3 = (state[3] or 0) + deltas[3]
        state[:] = [p0, p1, p2, p3]
    else:
        p0, p1, p2, p3 = [reader.bits(4) for _ in range(4)]
        state[:] = [p0, p1, p2, p3]

    out = bytearray()
    previous_zero = False
    previous_run = False

    while True:
        tree = after_run_tree if previous_run else (after_zero_tree if previous_zero else literal_tree)
        symbol = decode_huffman_symbol(reader, tree)
        if symbol is None or symbol == 260:
            break

        if symbol == 256:
            value = decode_huffman_symbol(reader, zero_value_tree if previous_zero else value_tree)
            if value is None:
                break
            flag = reader.bit()
            run = reader.rice(p2 if flag == 0 else p3) + 1
            out += bytes([value]) * run
            previous_zero = value == 0
            previous_run = True
        elif symbol == 257:
            flag = reader.bit()
            run = reader.rice(p0 if flag == 0 else p1) + 1
            out += b"\x00" * run
            previous_zero = True
            previous_run = True
        elif symbol == 258:
            run = 2 + reader.bits(5)
            out += b"\x00" * run
            previous_zero = True
            previous_run = True
        elif symbol == 259:
            value = decode_huffman_symbol(reader, zero_value_tree if previous_zero else value_tree)
            if value is None:
                break
            run = 2 + reader.bits(3)
            out += bytes([value]) * run
            previous_zero = value == 0
            previous_run = True
        else:
            if not 0 <= symbol <= 255:
                raise ValueError(f"bad entropy symbol {symbol}")
            out.append(symbol)
            previous_zero = symbol == 0
            previous_run = False

    return bytes(out)


def context_mtf_decode(data: bytes) -> bytes:
    tables = [list(range(256)) for _ in range(256)]
    previous = 0
    out = bytearray()
    for encoded in data:
        table = tables[previous]
        value = table[encoded]
        out.append(value)
        if encoded > 0:
            table[1:encoded + 1] = table[0:encoded]
            table[0] = value
        previous = value
    return bytes(out)


def inverse_bwt(data: bytes, primary_index: int) -> bytes:
    if not data:
        return b""

    counts = [0] * 256
    for value in data:
        counts[value] += 1

    starts = [0] * 256
    position = 1
    for value in range(256):
        starts[value] = position
        position += counts[value]

    next_table = [0] * (len(data) + 1)
    cursors = starts[:]
    for index, value in enumerate(data, 1):
        position = cursors[value]
        next_table[position] = index
        cursors[value] = position + 1

    current = primary_index + 1
    out = bytearray()
    for _ in range(len(data)):
        current = next_table[current]
        out.append(data[current - 1])
    return bytes(out)


def unpack_outer(encoded_text: str) -> bytes:
    packed = ascii85_ib1(encoded_text)
    pos = 0
    state: list[int | None] = [None, None, None, None]
    blocks = []

    while pos + 8 <= len(packed):
        primary = int.from_bytes(packed[pos:pos + 4], "little")
        size = int.from_bytes(packed[pos + 4:pos + 8], "little")
        pos += 8
        if pos + size > len(packed):
            raise ValueError("truncated compressed block")
        compressed = packed[pos:pos + size]
        pos += size
        stage1 = entropy_decode(compressed, state)
        stage2 = context_mtf_decode(stage1)
        blocks.append(inverse_bwt(stage2, primary))

    if pos != len(packed):
        raise ValueError(f"{len(packed) - pos} trailing bytes after compressed blocks")
    return b"".join(blocks)


class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def u8(self) -> int:
        value = self.data[self.pos]
        self.pos += 1
        return value

    def u16(self) -> int:
        value = int.from_bytes(self.data[self.pos:self.pos + 2], "little")
        self.pos += 2
        return value

    def u64(self) -> int:
        value = int.from_bytes(self.data[self.pos:self.pos + 8], "little", signed=False)
        self.pos += 8
        return value

    def i64(self) -> int:
        value = int.from_bytes(self.data[self.pos:self.pos + 8], "little", signed=True)
        self.pos += 8
        return value

    def f64(self) -> float:
        value = struct.unpack_from("<d", self.data, self.pos)[0]
        self.pos += 8
        return value

    def varuint(self) -> int:
        value = 0
        shift = 0
        while True:
            byte = self.u8()
            value |= (byte & 0x7F) << shift
            if byte < 0x80:
                return value
            shift += 7
            if shift > 70:
                raise ValueError("oversized varint")

    def varint(self) -> int:
        value = self.varuint()
        half = value // 2
        return half if value % 2 == 0 else -half - 1

    def raw(self, size: int) -> bytes:
        value = self.data[self.pos:self.pos + size]
        if len(value) != size:
            raise EOFError("serialized stream ended")
        self.pos += size
        return value


def decode_lua_string(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def read_constant(reader: Reader) -> dict[str, Any]:
    tag = reader.u8()
    subtype = None

    if tag == 0:
        subtype = reader.u8()
        if subtype == 0:
            value = decode_lua_string(reader.raw(reader.varuint()))
            kind = "string"
        else:
            value = None
            kind = "nil"
    elif tag == 1:
        subtype = reader.u8()
        value = reader.varint() if subtype == 1 else reader.i64()
        kind = "int"
    elif tag == 2:
        subtype = reader.u8()
        value = reader.varuint() if subtype == 1 else reader.u64()
        kind = "uint"
    elif tag == 3:
        value = reader.f64()
        kind = "double"
    elif tag == 4:
        subtype = reader.u8()
        value = reader.varint() if subtype == 1 else reader.f64()
        kind = "number"
    elif tag == 5:
        value = reader.u8() != 0
        kind = "boolean"
    else:
        value = None
        kind = f"unknown_{tag}"

    return {"tag": tag, "subtype": subtype, "kind": kind, "value": value}


def read_delta_array(reader: Reader, count: int) -> list[int]:
    value = 0
    out = []
    for _ in range(count):
        value += reader.varint()
        out.append(value)
    return out


def parse_prototype(reader: Reader, depth: int = 0) -> dict[str, Any]:
    start = reader.pos

    # Per-prototype field permutation used by the VM instruction tables.
    field_permutation = list(reader.raw(14))
    frame_size = reader.varuint()
    prototype_flag = reader.u8() == 1

    child_count = reader.varuint()
    children = [parse_prototype(reader, depth + 1) for _ in range(child_count)]

    captures = None
    if reader.u8() != 0:
        captures = []
        capture_count = reader.varuint()
        slot = 0
        for _ in range(capture_count):
            local_capture = reader.u8() != 0
            slot += reader.varint()
            captures.append({"local": local_capture, "slot": slot})

    num_params = reader.u8()

    paths = []
    for _ in range(reader.varuint()):
        paths.append([reader.varuint() for _ in range(reader.varuint())])

    upvalue_refs = []
    slot = 0
    for _ in range(reader.varuint()):
        local_ref = reader.u8() != 0
        slot += reader.varint()
        extra = reader.u8()
        upvalue_refs.append({"local": local_ref, "slot": slot, "extra": extra})

    constants = [read_constant(reader) for _ in range(reader.varuint())]

    instructions = []
    acc_a = acc_b = acc_c = acc_d = 0
    instruction_count = reader.varuint()

    for pc in range(1, instruction_count + 1):
        opcode = reader.varuint()
        flag = reader.u8() != 0
        flag_b = reader.u8() == 1
        flag_c = reader.u8() == 1
        mode = reader.u8()

        a = b = c = d = None

        if mode == 1:
            count = reader.u16()
            b_values = read_delta_array(reader, count)
            c_values = read_delta_array(reader, count)
            a_values = read_delta_array(reader, count)
            # The serializer interleaves the three streams, so redo it correctly.
            # We cannot use the three reads above; mode 1 is parsed below from raw order.
            raise AssertionError("mode 1 placeholder should never run")
        elif mode == 2:
            raise AssertionError("mode 2 placeholder should never run")
        elif mode == 3:
            raise AssertionError("mode 3 placeholder should never run")
        elif mode == 4:
            raise AssertionError("mode 4 placeholder should never run")
        else:
            acc_b += reader.varint()
            acc_c += reader.varint()
            acc_a += reader.varint()
            acc_d += reader.varint()
            a, b, c, d = acc_a, acc_b, acc_c, acc_d

        instructions.append({
            "pc": pc,
            "opcode": opcode,
            "A": a,
            "B": b,
            "C": c,
            "D": d,
            "mode": mode,
            "flag": flag,
            "flag_b": flag_b,
            "flag_c": flag_c,
        })

    return {
        "depth": depth,
        "start": start,
        "end": reader.pos,
        "field_permutation": field_permutation,
        "frame_size": frame_size,
        "prototype_flag": prototype_flag,
        "num_params": num_params,
        "captures": captures,
        "paths": paths,
        "upvalue_refs": upvalue_refs,
        "constants": constants,
        "instructions": instructions,
        "children": children,
    }


def parse_instruction(reader: Reader, pc: int, accum: list[int]) -> dict[str, Any]:
    opcode = reader.varuint()
    flag = reader.u8() != 0
    flag_b = reader.u8() == 1
    flag_c = reader.u8() == 1
    mode = reader.u8()
    a = b = c = d = None

    if mode == 1:
        count = reader.u16()
        x1 = x2 = x3 = 0
        q1, q2, q3 = [], [], []
        for _ in range(count):
            x1 += reader.varint()
            x2 += reader.varint()
            x3 += reader.varint()
            q1.append(x1)
            q2.append(x2)
            q3.append(x3)
        a, b, c = q3, q1, q2
    elif mode == 2:
        count = reader.u16()
        x1 = x2 = 0
        q1, q2 = [], []
        for _ in range(count):
            x1 += reader.varint()
            x2 += reader.varint()
            q1.append(x1)
            q2.append(x2)
        a, b = q2, q1
    elif mode == 3:
        count = reader.u16()
        x = 0
        q = []
        for _ in range(count):
            x += reader.varint()
            q.append(x)
        a = q
    elif mode == 4:
        count = reader.u16()
        x1 = x2 = x3 = x4 = 0
        q1, q2, q3, q4 = [], [], [], []
        for _ in range(count):
            x1 += reader.varint()
            x2 += reader.varint()
            x3 += reader.varint()
            x4 += reader.varint()
            q1.append(x1)
            q2.append(x2)
            q3.append(x3)
            q4.append(x4)
        a, b, c, d = q3, q1, q2, q4
    else:
        accum[1] += reader.varint()  # B
        accum[2] += reader.varint()  # C
        accum[0] += reader.varint()  # A
        accum[3] += reader.varint()  # D/aux
        a, b, c, d = accum

    return {
        "pc": pc,
        "opcode": opcode,
        "A": a,
        "B": b,
        "C": c,
        "D": d,
        "mode": mode,
        "flag": flag,
        "flag_b": flag_b,
        "flag_c": flag_c,
    }


def parse_prototype_fixed(reader: Reader, depth: int = 0) -> dict[str, Any]:
    start = reader.pos
    field_permutation = list(reader.raw(14))
    frame_size = reader.varuint()
    prototype_flag = reader.u8() == 1
    children = [parse_prototype_fixed(reader, depth + 1) for _ in range(reader.varuint())]

    captures = None
    if reader.u8() != 0:
        captures = []
        slot = 0
        for _ in range(reader.varuint()):
            local_capture = reader.u8() != 0
            slot += reader.varint()
            captures.append({"local": local_capture, "slot": slot})

    num_params = reader.u8()

    paths = []
    for _ in range(reader.varuint()):
        paths.append([reader.varuint() for _ in range(reader.varuint())])

    upvalue_refs = []
    slot = 0
    for _ in range(reader.varuint()):
        local_ref = reader.u8() != 0
        slot += reader.varint()
        upvalue_refs.append({"local": local_ref, "slot": slot, "extra": reader.u8()})

    constants = [read_constant(reader) for _ in range(reader.varuint())]

    accum = [0, 0, 0, 0]
    instructions = [
        parse_instruction(reader, pc, accum)
        for pc in range(1, reader.varuint() + 1)
    ]

    return {
        "depth": depth,
        "start": start,
        "end": reader.pos,
        "field_permutation": field_permutation,
        "frame_size": frame_size,
        "prototype_flag": prototype_flag,
        "num_params": num_params,
        "captures": captures,
        "paths": paths,
        "upvalue_refs": upvalue_refs,
        "constants": constants,
        "instructions": instructions,
        "children": children,
    }


def parse_serialized(data: bytes) -> dict[str, Any]:
    reader = Reader(data)
    root = parse_prototype_fixed(reader)
    if reader.pos != len(data):
        raise ValueError(f"parser stopped at {reader.pos}, stream size is {len(data)}")
    return root


def flatten_prototypes(root: dict[str, Any]) -> list[dict[str, Any]]:
    result = []

    def walk(proto: dict[str, Any]) -> None:
        proto["id"] = len(result)
        result.append(proto)
        for child in proto["children"]:
            walk(child)

    walk(root)
    return result


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


def write_dumps(out_dir: Path, serialized: bytes, root: dict[str, Any], opcode_map: dict[int, str]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "serialized.bin").write_bytes(serialized)

    prototypes = flatten_prototypes(root)

    constants_json = []
    strings = []
    constants_lines = []
    ir_lines = []

    for proto in prototypes:
        pid = proto["id"]
        constants_lines.append(f"\n== prototype {pid} depth={proto['depth']} constants={len(proto['constants'])} ==")
        for index, item in enumerate(proto["constants"]):
            value = json_value(item["value"])
            constants_json.append({
                "prototype": pid,
                "index": index,
                "kind": item["kind"],
                "tag": item["tag"],
                "subtype": item["subtype"],
                "value": value,
            })
            constants_lines.append(f"K{index:04d} {item['kind']:<8} {constant_text(value)}")
            if item["kind"] == "string":
                strings.append(f"P{pid}:K{index} {value}")

        ir_lines.append(
            f"\n== prototype {pid} depth={proto['depth']} params={proto['num_params']} "
            f"frame={proto['frame_size']} ins={len(proto['instructions'])} =="
        )
        ir_lines.append(f"field_permutation={proto['field_permutation']}")
        for ins in proto["instructions"]:
            opname = opcode_map.get(ins["opcode"], f"OP_{ins['opcode']:03d}")
            ir_lines.append(
                f"{ins['pc']:05d} {opname:<18} "
                f"A={ins['A']!r} B={ins['B']!r} C={ins['C']!r} D={ins['D']!r} "
                f"mode={ins['mode']} flags={int(ins['flag'])}{int(ins['flag_b'])}{int(ins['flag_c'])}"
            )

    opcode_counts = Counter(ins["opcode"] for proto in prototypes for ins in proto["instructions"])
    summary = {
        "serialized_bytes": len(serialized),
        "prototypes": len(prototypes),
        "constants": sum(len(proto["constants"]) for proto in prototypes),
        "strings": sum(1 for x in constants_json if x["kind"] == "string"),
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

    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2), "utf-8")
    (out_dir / "constants.json").write_text(json.dumps(constants_json, indent=2, ensure_ascii=False), "utf-8")
    (out_dir / "constants.txt").write_text("\n".join(constants_lines) + "\n", "utf-8")
    (out_dir / "strings.txt").write_text("\n".join(strings) + "\n", "utf-8")
    (out_dir / "ir.txt").write_text("\n".join(ir_lines) + "\n", "utf-8")


def lower_camel(name: str) -> str:
    if not name:
        return "value"
    if name.startswith("UI") and len(name) > 2:
        return "ui" + name[2:]
    if name.isupper():
        return name.lower()
    return name[0].lower() + name[1:]


def semantic_rename_lua(source: str) -> tuple[str, dict[str, str]]:
    candidates: list[tuple[str, str]] = []

    patterns = [
        (r"\blocal\s+([A-Za-z_]\w*)\s*=\s*Instance\s*\.\s*new\(\s*['\"]([^'\"]+)['\"]\s*\)", 2),
        (r"\blocal\s+([A-Za-z_]\w*)\s*=\s*game\s*:\s*GetService\(\s*['\"]([^'\"]+)['\"]\s*\)", 2),
        (r"\blocal\s+([A-Za-z_]\w*)\s*=\s*[^\n;]+:\s*WaitForChild\(\s*['\"]([^'\"]+)['\"]\s*\)", 2),
    ]

    for pattern, name_group in patterns:
        for match in re.finditer(pattern, source, re.I):
            candidates.append((match.group(1), lower_camel(match.group(name_group))))

    existing = set(re.findall(r"\blocal\s+([A-Za-z_]\w*)", source))
    reserved = set(existing)
    mapping: dict[str, str] = {}

    for old, base in candidates:
        if old in mapping:
            continue
        new = base
        suffix = 2
        while new in reserved and new != old:
            new = f"{base}{suffix}"
            suffix += 1
        mapping[old] = new
        reserved.add(new)

    for old, new in sorted(mapping.items(), key=lambda pair: -len(pair[0])):
        source = re.sub(rf"\b{re.escape(old)}\b", new, source)

    return source, mapping


def main() -> None:
    parser = argparse.ArgumentParser(description="IronBrew1 format extractor / IR dumper")
    parser.add_argument("input", type=Path, help="IronBrew1-obfuscated Lua source")
    parser.add_argument("-o", "--out", type=Path, default=Path("ib1_out"))
    parser.add_argument("--opcode-map", type=Path, help="JSON object mapping encoded opcode numbers to names")
    parser.add_argument("--rename", type=Path, help="post-process a decompiled Lua file with semantic names")
    args = parser.parse_args()

    source = args.input.read_text("utf-8", errors="replace")
    encoded = find_encoded_blob(source)
    serialized = unpack_outer(encoded)
    root = parse_serialized(serialized)
    opcode_map = load_opcode_map(args.opcode_map)
    write_dumps(args.out, serialized, root, opcode_map)

    if args.rename:
        lua = args.rename.read_text("utf-8", errors="replace")
        renamed, mapping = semantic_rename_lua(lua)
        renamed_path = args.out / "renamed.lua"
        renamed_path.write_text(renamed, "utf-8")
        (args.out / "renames.json").write_text(json.dumps(mapping, indent=2), "utf-8")

    summary = json.loads((args.out / "summary.json").read_text("utf-8"))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
