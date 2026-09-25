import sys
import re
from pathlib import Path

def fold_sun_tzu_expressions(lua_code: str) -> str:
    res = re.sub(
        r'\(\(function\(A\)\s*return\s*\(\s*#A\s*-\s*(\d+)\s*\)\s*end\)\(\'([^\']+)\'\)\)',
        lambda m: str(len(m.group(2)) - int(m.group(1))),
        lua_code
    )
    res = re.sub(
        r'\(\s*#\(\'([^\']+)\'\)\s*-\s*(\d+)\s*\)',
        lambda m: str(len(m.group(1)) - int(m.group(2))),
        res
    )
    res = re.sub(
        r'#\(\'([^\']+)\'\)',
        lambda m: str(len(m.group(1))),
        res
    )
    return res

def parse_lua_string_bytes(escaped_str: str) -> list:
    bytes_list = []
    i = 0
    n = len(escaped_str)
    while i < n:
        if escaped_str[i] == '\\':
            i += 1
            num_str = ""
            while i < n and escaped_str[i].isdigit() and len(num_str) < 3:
                num_str += escaped_str[i]
                i += 1
            if num_str:
                bytes_list.append(int(num_str))
            else:
                if i < n:
                    ch = escaped_str[i]
                    if ch == 'n': bytes_list.append(10)
                    elif ch == 'r': bytes_list.append(13)
                    elif ch == 't': bytes_list.append(9)
                    elif ch == '\\': bytes_list.append(92)
                    elif ch == '"': bytes_list.append(34)
                    else: bytes_list.append(ord(ch))
                    i += 1
        else:
            bytes_list.append(ord(escaped_str[i]))
            i += 1
    return bytes_list

def xor_decrypt_bytes(byte_vals: list, key: str) -> str:
    if not key:
        return "".join(chr(b) for b in byte_vals)
    key_bytes = [ord(c) for c in key]
    key_len = len(key_bytes)
    res = []
    for i, b in enumerate(byte_vals):
        res.append(chr(b ^ key_bytes[i % key_len]))
    return "".join(res)

def extract_keys_from_preamble(code: str) -> dict:
    folded = fold_sun_tzu_expressions(code[:40000])
    m_base = re.search(r'local\s+([a-zA-Z0-9_]+)\s*=\s*"([a-zA-Z0-9_]{8,24})"', folded)
    base_key = m_base.group(2) if m_base else None

    m_z = re.search(r'local\s+[a-zA-Z0-9_]+\s*=\s*[a-zA-Z0-9_]+\s*\(\s*"([^"]+)"\s*,\s*' + re.escape(m_base.group(1) if m_base else '') + r'\s*\)', folded)
    key_B = None
    if m_z and base_key:
        raw_b = parse_lua_string_bytes(m_z.group(1))
        key_B = xor_decrypt_bytes(raw_b, base_key)

    m_d = re.search(r'local\s+[a-zA-Z0-9_]+\s*=\s*[a-zA-Z0-9_]+\s*\(\s*"([^"]+)"\s*,\s*[a-zA-Z0-9_]+\s*\)', folded[m_z.end():m_z.end()+1500] if m_z else folded)
    key_D = None
    if m_d and key_B:
        raw_d = parse_lua_string_bytes(m_d.group(1))
        key_D = xor_decrypt_bytes(raw_d, key_B)

    return {"base_key": base_key, "key_B": key_B, "key_D": key_D}

def decrypt_constant(raw_str: str, key_D: str, key_B: str) -> str:
    b1 = parse_lua_string_bytes(raw_str)
    s1 = xor_decrypt_bytes(b1, key_D)
    b2 = [ord(c) for c in s1]
    return xor_decrypt_bytes(b2, key_B)

def dump_constants(input_path: str, output_path: str = None) -> list:
    with open(input_path, "r", encoding="utf-8", errors="ignore") as f:
        src = f.read()

    keys = extract_keys_from_preamble(src)
    key_B, key_D = keys["key_B"], keys["key_D"]
    if not key_B or not key_D:
        raise ValueError("Could not extract Boronide keys")

    constants = []
    seen = set()

    pos = src.find("[(b._iBU6U)]={")
    while pos != -1:
        end_pos = src.find("}}", pos)
        chunk = src[pos:end_pos + 2]
        for m in re.finditer(r'\{("([^"]+)"|([0-9\.\-]+))\}', chunk):
            if m.group(2) is not None:
                dec = decrypt_constant(m.group(2), key_D, key_B)
            else:
                dec = m.group(3)
            if dec not in seen:
                seen.add(dec)
                constants.append(dec)
        pos = src.find("[(b._iBU6U)]={", end_pos)

    for m in re.finditer(r'c\s*\(\s*"([^"]+)"\s*\)\s*\(\s*\)', src):
        dec = decrypt_constant(m.group(1), key_D, key_B)
        if dec not in seen:
            seen.add(dec)
            constants.append(dec)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            for item in constants:
                f.write(repr(item) + "\n")

    return constants

if __name__ == "__main__":
    src_file = sys.argv[1] if len(sys.argv) > 1 else "examples/boronide maximum.lua"
    dst_file = sys.argv[2] if len(sys.argv) > 2 else "constants_dump.txt"
    dump_constants(src_file, dst_file)