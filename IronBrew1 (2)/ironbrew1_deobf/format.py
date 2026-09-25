from __future__ import annotations

import json
import math
import struct
from typing import Any

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


