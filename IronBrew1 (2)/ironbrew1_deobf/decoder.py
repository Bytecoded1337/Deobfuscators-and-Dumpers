from __future__ import annotations

import re

LEAF = -1


def find_encoded_blob(source: str) -> str:
    candidates: list[str] = []
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
        return quotient if width == 0 else quotient * (1 << width) + self.bits(width)


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
        width = reader.gamma() if index == 1 else (last_width if reader.bit() == 1 else reader.gamma())
        groups.setdefault(width, []).append(symbol)
        max_width = max(max_width, width)
        last_symbol, last_width = symbol, width
    code = 0
    previous_width = 0
    for width in range(1, max_width + 1):
        symbols = groups.get(width)
        if not symbols:
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
            run = reader.rice(p2 if reader.bit() == 0 else p3) + 1
            out += bytes([value]) * run
            previous_zero, previous_run = value == 0, True
        elif symbol == 257:
            run = reader.rice(p0 if reader.bit() == 0 else p1) + 1
            out += b"\x00" * run
            previous_zero, previous_run = True, True
        elif symbol == 258:
            run = 2 + reader.bits(5)
            out += b"\x00" * run
            previous_zero, previous_run = True, True
        elif symbol == 259:
            value = decode_huffman_symbol(reader, zero_value_tree if previous_zero else value_tree)
            if value is None:
                break
            run = 2 + reader.bits(3)
            out += bytes([value]) * run
            previous_zero, previous_run = value == 0, True
        else:
            if not 0 <= symbol <= 255:
                raise ValueError(f"bad entropy symbol {symbol}")
            out.append(symbol)
            previous_zero, previous_run = symbol == 0, False
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
    blocks: list[bytes] = []
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
