import sys
import os
import re
import struct
import argparse
import time
from typing import Dict, List, Any, Optional, Set, Tuple

def decompress_lzw(encoded_str: str) -> bytes:
    dict_size = 256
    dictionary = {i: bytes([i]) for i in range(dict_size)}
    pos = 0
    total_len = len(encoded_str)

    def read_code() -> int:
        nonlocal pos
        digit_len = int(encoded_str[pos:pos + 1], 36)
        pos += 1
        val = int(encoded_str[pos:pos + digit_len], 36)
        pos += digit_len
        return val

    code = read_code()
    curr_bytes = bytes([code])
    result = [curr_bytes]

    while pos < total_len:
        code = read_code()
        if code in dictionary:
            entry = dictionary[code]
        elif code == dict_size:
            entry = curr_bytes + curr_bytes[0:1]
        else:
            entry = curr_bytes + curr_bytes[0:1]

        dictionary[dict_size] = curr_bytes + entry[0:1]
        dict_size += 1
        result.append(entry)
        curr_bytes = entry

    return b"".join(result)

def get_bits(val: int, start: int, end: Optional[int] = None) -> int:
    if end is not None:
        mask = (1 << (end - start + 1)) - 1
        return (val >> (start - 1)) & mask
    else:
        return (val >> (start - 1)) & 1

class BytecodeReader:
    def __init__(self, data: bytes, xor_key: int):
        self.data = data
        self.xor_key = xor_key
        self.pos = 0

    def read_u8(self) -> int:
        b = self.data[self.pos] ^ self.xor_key
        self.pos += 1
        return b

    def read_u16(self) -> int:
        b0 = self.data[self.pos] ^ self.xor_key
        b1 = self.data[self.pos + 1] ^ self.xor_key
        self.pos += 2
        return (b1 << 8) | b0

    def read_u32(self) -> int:
        b = [self.data[self.pos + i] ^ self.xor_key for i in range(4)]
        self.pos += 4
        return (b[3] << 24) | (b[2] << 16) | (b[1] << 8) | b[0]

    def read_float(self) -> float:
        l = self.read_u32()
        e = self.read_u32()
        raw_bytes = struct.pack('<II', l, e)
        return struct.unpack('<d', raw_bytes)[0]

    def read_string(self, length: Optional[int] = None) -> str:
        if length is None:
            length = self.read_u32()
            if length == 0:
                return ""
        s_bytes = bytes([self.data[self.pos + i] ^ self.xor_key for i in range(length)])
        self.pos += length
        return s_bytes.decode('latin1', errors='replace')

def extract_payload_string(text: str) -> str:
    idx = 0
    while idx < len(text):
        pos_single = text.find("('", idx)
        pos_double = text.find('("', idx)
        if pos_single == -1 and pos_double == -1:
            break
        if pos_single != -1 and (pos_double == -1 or pos_single < pos_double):
            pos = pos_single
            quote = "'"
        else:
            pos = pos_double
            quote = '"'

        end_pos = text.find(quote + ")", pos + 2)
        if end_pos != -1 and (end_pos - (pos + 2)) > 100:
            candidate = text[pos + 2:end_pos]
            if candidate[:30].isalnum():
                return candidate
        idx = pos + 2

    best = ""
    for m in re.finditer(r"['\"]([0-9A-Za-z]{100,})['\"]", text):
        if len(m.group(1)) > len(best):
            best = m.group(1)
    if best:
        return best

    raise ValueError("Could not find IronBrew 2 encoded bytecode string in source.")

def detect_ironbrew_variant(script_text: str) -> Dict[str, Any]:
    payload = extract_payload_string(script_text)

    vm_pos = script_text.find('while true do')
    preamble = script_text[:vm_pos] if vm_pos != -1 else script_text[:30000]

    if "C(B, 1, 2)" in preamble or "C(B,1,2)" in preamble or "1048575" in preamble:
        m_base = re.search(r',\s*(\d{1,3})\s*\)\s*[a-zA-Z_]\w*\s*=\s*[a-zA-Z_]\w*\s*\+\s*4', preamble)
        base_xor = int(m_base.group(1)) if m_base else 47

        m_inst = re.findall(r'\(\s*\)\s*,\s*(\d{1,3})\s*\)', preamble)
        inst_xor1 = int(m_inst[0]) if len(m_inst) >= 1 else 56
        inst_xor2 = int(m_inst[1]) if len(m_inst) >= 2 else 186

        return {
            "variant": 2,
            "payload": payload,
            "base_xor": base_xor,
            "inst_xor1": inst_xor1,
            "inst_xor2": inst_xor2
        }
    else:
        m_xor = re.findall(r',\s*(\d{1,3})\s*\)\s*;\s*\w+\s*=\s*\w+\s*\+\s*1\s*;\s*return', preamble)
        if m_xor:
            xor_key = int(m_xor[0])
        else:
            m_xor2 = re.search(r',\s*(\d{1,3})\s*\)\s*[a-zA-Z_]\w*\s*=\s*[a-zA-Z_]\w*\s*\+\s*4', preamble)
            xor_key = int(m_xor2.group(1)) if m_xor2 else 202

        float_fn = None
        pos_f = preamble.find('2^52')
        if pos_f != -1:
            prefix_f = preamble[max(0, pos_f - 400):pos_f]
            m_fn = re.findall(r'local\s+function\s+([a-zA-Z_]\w*)\s*\(', prefix_f)
            if m_fn:
                float_fn = m_fn[-1]

        m_const_loop = re.search(r'for\s+\w+\s*=\s*1\s*,\s*\w+\s+do\s+local\s+\w+\s*=\s*\w+\(\);local\s+\w+;(.*?)(?:end;\s*\w+\[3\]|end;[a-zA-Z_]\w*\[3\])', preamble, re.DOTALL)
        const_map = {0: 'bool', 1: 'float', 2: 'string'}
        if m_const_loop:
            const_map = {}
            for m in re.finditer(r'(?:if|elseif)\s*\(\s*\w+\s*==\s*(\d+)\s*\)\s*then\s*(.*?)(?=(?:elseif|else|end))', m_const_loop.group(1), re.DOTALL):
                ct = int(m.group(1))
                branch = m.group(2)
                if '~=0' in branch or '==0' in branch:
                    const_map[ct] = 'bool'
                elif float_fn and f'{float_fn}(' in branch:
                    const_map[ct] = 'float'
                else:
                    const_map[ct] = 'string'

        return {
            "variant": 1,
            "payload": payload,
            "xor_key": xor_key,
            "const_map": const_map
        }

def deserialize_proto_v1(reader: BytecodeReader, const_map: Optional[Dict[int, str]] = None) -> Dict[str, Any]:
    if const_map is None:
        const_map = {0: 'bool', 1: 'float', 2: 'string'}

    instructions = {}
    child_protos = {}

    num_consts = reader.read_u32()
    consts = {}
    for i in range(1, num_consts + 1):
        c_type = reader.read_u8()
        kind = const_map.get(c_type)
        if kind == 'bool':
            c_val = (reader.read_u8() != 0)
        elif kind == 'float':
            c_val = reader.read_float()
        elif kind == 'string':
            c_val = reader.read_string()
        else:
            c_val = None
        consts[i] = c_val

    num_params = reader.read_u8()
    num_children = reader.read_u32()
    for i in range(num_children):
        child_protos[i] = deserialize_proto_v1(reader, const_map)

    num_inst = reader.read_u32()
    for i in range(1, num_inst + 1):
        flags = reader.read_u8()
        if get_bits(flags, 1) == 0:
            c = get_bits(flags, 2, 3)
            t = get_bits(flags, 4, 6)
            inst = [reader.read_u16(), reader.read_u16(), None, None, None]
            if c == 0:
                inst[2] = reader.read_u16()
                inst[4] = reader.read_u16()
            elif c == 1:
                inst[2] = reader.read_u32()
            elif c == 2:
                inst[2] = reader.read_u32() - (1 << 16)
            elif c == 3:
                inst[2] = reader.read_u32() - (1 << 16)
                inst[4] = reader.read_u16()

            if get_bits(t, 1) == 1:
                inst[1] = consts.get(inst[1], inst[1])
            if get_bits(t, 2) == 1:
                inst[2] = consts.get(inst[2], inst[2])
            if get_bits(t, 3) == 1:
                inst[4] = consts.get(inst[4], inst[4])

            instructions[i] = inst

    return {
        "variant": 1,
        "consts": consts,
        "num_params": num_params,
        "protos": child_protos,
        "instructions": instructions
    }

def deserialize_proto_v2(reader: BytecodeReader, inst_xor1: int = 56, inst_xor2: int = 186) -> Dict[str, Any]:
    protos = {}

    num_protos = reader.read_u32()
    for i in range(num_protos):
        protos[i] = deserialize_proto_v2(reader, inst_xor1, inst_xor2)

    num_consts = reader.read_u32()
    consts = {}
    for i in range(1, num_consts + 1):
        c_type = reader.read_u8()
        if c_type == 3:
            c_val = (reader.read_u8() != 0)
        elif c_type == 1:
            c_val = reader.read_float()
        elif c_type == 0:
            c_val = reader.read_string()
        else:
            c_val = None
        consts[i] = c_val

    num_params = reader.read_u8()

    num_inst = reader.read_u32()
    instructions = {}
    for i in range(1, num_inst + 1):
        B = reader.read_u32() ^ inst_xor1
        l = reader.read_u32() ^ inst_xor2
        e = get_bits(B, 1, 2)
        opcode = get_bits(l, 1, 11)
        A = get_bits(B, 3, 11)
        inst = [opcode, A, None, None, None]
        if e == 0:
            inst[2] = get_bits(B, 12, 20)
            inst[4] = get_bits(B, 21, 29)
        elif e == 1:
            inst[2] = get_bits(l, 12, 33)
        elif e == 2:
            inst[2] = get_bits(l, 12, 32) - 1048575
        elif e == 3:
            inst[2] = get_bits(l, 12, 32) - 1048575
            inst[4] = get_bits(B, 21, 29)
        instructions[i] = inst

    return {
        "variant": 2,
        "consts": consts,
        "num_params": num_params,
        "protos": protos,
        "instructions": instructions
    }

def deserialize_script(script_text: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    meta = detect_ironbrew_variant(script_text)
    raw_data = decompress_lzw(meta["payload"])

    if meta["variant"] == 1:
        reader = BytecodeReader(raw_data, meta["xor_key"])
        root = deserialize_proto_v1(reader, meta.get("const_map"))
    else:
        reader = BytecodeReader(raw_data, meta["base_xor"])
        root = deserialize_proto_v2(reader, meta["inst_xor1"], meta["inst_xor2"])

    meta["data_size"] = len(raw_data)
    return root, meta

class AtomicOp:
    def __init__(self, op_name: str, op_type: str = 'ABC', raw_code: str = '', details: Optional[Dict[str, Any]] = None):
        self.op_name = op_name
        self.op_type = op_type
        self.raw_code = raw_code
        self.details = details or {}

    def __repr__(self):
        return f"AtomicOp({self.op_name}, {self.op_type})"

class VMAnalyzer:
    def __init__(self, script_text: str, op_var: str = 'o'):
        self.script_text = script_text
        self.op_var = op_var
        self.vm_code = ""
        self.ast = None
        self.handlers: Dict[int, str] = {}
        self.op_mappings: Dict[int, List[AtomicOp]] = {}
        self.reg_var = 'l'
        self.const_var = 'B'
        self.env_var = 'G'
        self.pc_var = 'D'
        self.inst_var = 'C'
        self._extract_vm_and_build_ast()

    def _extract_vm_and_build_ast(self):
        vm_pos = self.script_text.find('while true do')
        if vm_pos == -1:
            raise ValueError("Could not find VM dispatch loop ('while true do') in script.")

        m_if = re.search(rf'\bif\s+{self.op_var}\b', self.script_text[vm_pos:])
        if not m_if:
            m_op = re.search(r'while\s+true\s+do\s+([a-zA-Z_]\w*)\s*=\s*[a-zA-Z_]\w*\[([a-zA-Z_]\w*)\]\s*;\s*([a-zA-Z_]\w*)\s*=\s*\1\[1\]', self.script_text)
            if m_op:
                self.inst_var = m_op.group(1)
                self.pc_var = m_op.group(2)
                self.op_var = m_op.group(3)
                m_if = re.search(rf'\bif\s+{self.op_var}\b', self.script_text[vm_pos:])

        first_if_idx = vm_pos + (m_if.start() if m_if else len('while true do'))
        end_idx = self.script_text.rfind('end;return')
        if end_idx == -1:
            end_idx = self.script_text.rfind('end; return')
        if end_idx == -1:
            end_idx = len(self.script_text)

        self.vm_code = self.script_text[first_if_idx:end_idx]

        preamble = self.script_text[vm_pos:first_if_idx]
        m_inst = re.search(r'([a-zA-Z_]\w*)\s*=\s*([a-zA-Z_]\w*)\[([a-zA-Z_]\w*)\]\s*;\s*([a-zA-Z_]\w*)\s*=\s*\1\[1\]', preamble)
        if m_inst:
            self.inst_var = m_inst.group(1)
            self.pc_var = m_inst.group(3)
            self.op_var = m_inst.group(4)

        m_reg = re.search(rf'([a-zA-Z_]\w*)\[{self.inst_var}\[2\]\]', self.vm_code)
        if m_reg:
            self.reg_var = m_reg.group(1)

        m_env = re.search(r'local function \w+\s*\([^)]*,([^,)]*)\)\s*local \w+=.*?return function\(\.\.\.\)', self.script_text[:vm_pos])
        if m_env:
            self.env_var = m_env.group(1).strip()

        m_wrap = re.search(r'local function ([a-zA-Z_]\w*)\s*\([^)]*\)\s*local [a-zA-Z_]\w*=[a-zA-Z_]\w*\[1\];.*?return function\(\.\.\.\)', self.script_text[:vm_pos])
        self.closure_var = m_wrap.group(1).strip() if m_wrap else 'W'

        tokens = self._tokenize_dispatch(self.vm_code)
        self.ast = self._parse_ast(tokens)

    def _tokenize_dispatch(self, code: str):
        clean_code = re.sub(r'--.*$', '', code, flags=re.MULTILINE)
        token_pattern = re.compile(
            r'\b(if|elseif)\b\s*(.*?)\s*\bthen\b|\b(else)\b|\b(do)\b|\b(function)\b|\b(end)\b',
            re.DOTALL
        )
        tokens = []
        last_end = 0
        internal_depth = 0

        for m in token_pattern.finditer(clean_code):
            start, end = m.span()
            kw_if, cond, kw_else, kw_do, kw_func, kw_end = m.groups()

            chunk = clean_code[last_end:start]
            if chunk:
                tokens.append(('CODE', chunk))

            if kw_if:
                is_elseif = (kw_if == 'elseif')
                is_disp = (internal_depth == 0 and
                           bool(re.search(rf'\b{self.op_var}\b', cond)) and
                           not bool(re.search(r'\b[elC]\[', cond)))
                if is_disp:
                    tokens.append(('DISP_IF' if not is_elseif else 'DISP_ELSEIF', cond.strip()))
                else:
                    if not is_elseif:
                        internal_depth += 1
                    tokens.append(('CODE', m.group(0)))
            elif kw_else:
                if internal_depth == 0:
                    tokens.append(('DISP_ELSE', None))
                else:
                    tokens.append(('CODE', m.group(0)))
            elif kw_do or kw_func:
                internal_depth += 1
                tokens.append(('CODE', m.group(0)))
            elif kw_end:
                if internal_depth > 0:
                    internal_depth -= 1
                    tokens.append(('CODE', m.group(0)))
                else:
                    tokens.append(('DISP_END', None))

            last_end = end

        chunk = clean_code[last_end:]
        if chunk:
            tokens.append(('CODE', chunk))
        return tokens

    def _parse_ast(self, tokens):
        pos = 0

        def parse_block():
            nonlocal pos
            nodes = []
            while pos < len(tokens):
                t_type, t_val = tokens[pos]
                if t_type in ('DISP_ELSEIF', 'DISP_ELSE', 'DISP_END'):
                    break
                elif t_type == 'CODE':
                    nodes.append(('CODE', t_val))
                    pos += 1
                elif t_type == 'DISP_IF':
                    nodes.append(parse_if())
                else:
                    pos += 1
            return nodes

        def parse_if():
            nonlocal pos
            _, cond = tokens[pos]
            pos += 1
            block = parse_block()
            branches = [(cond, block)]

            while pos < len(tokens) and tokens[pos][0] == 'DISP_ELSEIF':
                _, else_cond = tokens[pos]
                pos += 1
                else_block = parse_block()
                branches.append((else_cond, else_block))

            else_branch = None
            if pos < len(tokens) and tokens[pos][0] == 'DISP_ELSE':
                pos += 1
                else_branch = parse_block()

            if pos < len(tokens) and tokens[pos][0] == 'DISP_END':
                pos += 1

            return ('IF', branches, else_branch)

        return parse_block()

    def _eval_ast(self, node_list, op_val: int) -> str:
        codes = []
        for item in node_list:
            if item[0] == 'CODE':
                codes.append(item[1])
            elif item[0] == 'IF':
                _, branches, else_branch = item
                taken = False
                for cond, block in branches:
                    py_cond = cond.replace('~=', '!=').replace('and', ' and ').replace('or', ' or ').replace('not', ' not ')
                    try:
                        res = eval(py_cond, {self.op_var: op_val})
                    except Exception:
                        res = False
                    if res:
                        codes.append(self._eval_ast(block, op_val))
                        taken = True
                        break
                if not taken and else_branch:
                    codes.append(self._eval_ast(else_branch, op_val))
        return " ".join(codes).strip()

    def get_handler_code(self, op_val: int) -> str:
        if op_val not in self.handlers:
            self.handlers[op_val] = self._eval_ast(self.ast, op_val)
        return self.handlers[op_val]

    def classify_atomic(self, code: str) -> AtomicOp:
        raw = code.strip()
        compact = raw.replace(' ', '')
        reg = self.reg_var
        inst = self.inst_var
        env = self.env_var

        if (hasattr(self, 'closure_var') and f'{self.closure_var}(' in raw) or 'W(U[' in raw or '__index=' in raw or 'Q({' in raw or 'W(E,' in raw:
            return AtomicOp('CLOSURE', 'ABx', raw)

        if 'return' in raw:
            return AtomicOp('RETURN', 'ABC', raw)

        if compact.startswith(f'{reg}[{inst}[2]]=Z[') or f'{reg}[{inst}[2]]=Z[{inst}[3]]' in compact:
            return AtomicOp('GETUPVAL', 'ABC', raw)
        if compact.startswith('Z[') or f'Z[{inst}[3]]={reg}[' in compact:
            return AtomicOp('SETUPVAL', 'ABC', raw)

        m_setg = re.match(rf'^([a-zA-Z_]\w*)\[.*?\]={reg}\[{inst}\[2\]\]', compact)
        if m_setg:
            tbl = m_setg.group(1)
            if tbl not in (reg, 'Z', inst):
                return AtomicOp('SETGLOBAL', 'ABx', raw)

        if re.search(rf'{reg}\[{inst}\[2\]\]={env}\[', compact) or f'{reg}[{inst}[2]]={env}[' in compact:
            return AtomicOp('GETGLOBAL', 'ABx', raw)

        if re.search(rf'{reg}\[\w+\+1\]=\w+;?{reg}\[\w+\]=\w+\[{inst}\[4\]\]', compact):
            return AtomicOp('SELF', 'ABC', raw)
        if f'{reg}[{inst}[2]+1]=' in compact or ('+1]=' in compact and f'[{inst}[4]]' in compact):
            return AtomicOp('SELF', 'ABC', raw)

        if 'for' not in raw and 'while' not in raw:
            if re.search(rf'{reg}\[[a-zA-Z_]\w*\]\(', compact) or re.search(rf'=\s*{reg}\[[a-zA-Z_]\w*\]\(', raw):
                return AtomicOp('CALL', 'ABC', raw)
            if 'Q=e+l-1' in compact or 'Q=e+' in compact or 'i=l+e-1' in compact:
                return AtomicOp('CALL', 'ABC', raw)
            if '(F(' in compact or '(f(' in compact or '()};' in compact or '();' in compact:
                return AtomicOp('CALL', 'ABC', raw)

        if re.match(rf'^[a-zA-Z_]\w*={inst}\[2\];?$', compact):
            return AtomicOp('NOP', 'RAW', raw)

        if '..' in compact and ('for' in raw or '..=' in compact or f'..{reg}[' in compact):
            return AtomicOp('CONCAT', 'ABC', raw)

        if re.search(rf'{reg}\[[a-zA-Z_]\w*\]=nil', compact):
            return AtomicOp('LOADNIL', 'ABC', raw)

        if f'{reg}[{inst}[2]]=' in compact and ('~=0' in compact or '==0' in compact):
            return AtomicOp('LOADBOOL', 'ABC', raw)

        if f'{reg}[{inst}[2]][' in compact and '=' in compact:
            return AtomicOp('SETTABLE', 'ABC', raw)

        if f'{reg}[{inst}[2]]={{}}' in compact or f'{reg}[{inst}[2]]={{unpack' in compact:
            return AtomicOp('NEWTABLE', 'ABC', raw)

        if '==' in compact or '~=' in compact:
            return AtomicOp('EQ', 'ABC', raw)
        if '<=' in compact or '>=' in compact:
            return AtomicOp('LE', 'ABC', raw)
        if '<' in compact or '>' in compact:
            return AtomicOp('LT', 'ABC', raw)
        if f'ifnot{reg}[{inst}[2]]then' in compact or f'if{reg}[{inst}[2]]then' in compact:
            return AtomicOp('TEST', 'ABC', raw)

        if f'{self.pc_var}={self.pc_var}+{inst}[3]' in compact or f'{self.pc_var}={inst}[3]' in compact or f'{self.pc_var}={inst}[2]' in compact:
            return AtomicOp('JMP', 'AsBx', raw)

        if 'l[o+2]' in compact or 'l[o]-l[o+2]' in compact or f'{reg}[o+2]' in compact:
            return AtomicOp('FORLOOP', 'AsBx', raw)

        if f'{reg}[{inst}[2]]=' in compact and 'for' not in raw:
            for op_name, sym in [('ADD', '+'), ('SUB', '-'), ('MUL', '*'), ('DIV', '/'), ('MOD', '%'), ('POW', '^')]:
                if sym in compact and not compact.endswith(sym):
                    return AtomicOp(op_name, 'ABC', raw)

        stripped = re.sub(r'^(?:local\w+;)+', '', compact)
        if stripped.startswith(f'{reg}[{inst}[2]]={inst}[3]'):
            return AtomicOp('LOADK', 'ABx', raw)
        if stripped.startswith(f'{reg}[{inst}[2]]={env}['):
            return AtomicOp('GETGLOBAL', 'ABx', raw)
        if stripped.startswith(f'{reg}[{inst}[2]]={reg}[{inst}[3]]'):
            if '][' in stripped:
                return AtomicOp('GETTABLE', 'ABC', raw)
            return AtomicOp('MOVE', 'ABC', raw)

        m_getg = re.match(rf'^{reg}\[{inst}\[2\]\]=([a-zA-Z_]\w*)\[', compact)
        if m_getg:
            tbl = m_getg.group(1)
            if tbl == inst or tbl == self.const_var:
                return AtomicOp('LOADK', 'ABx', raw)
            elif tbl == 'Z':
                return AtomicOp('GETUPVAL', 'ABC', raw)
            elif tbl == env:
                return AtomicOp('GETGLOBAL', 'ABx', raw)
            elif tbl == reg:
                if compact.startswith(f'{reg}[{inst}[2]]={reg}[{inst}[3]];'):
                    return AtomicOp('MOVE', 'ABC', raw)
                elif '][' in compact:
                    return AtomicOp('GETTABLE', 'ABC', raw)
            else:
                return AtomicOp('GETGLOBAL', 'ABx', raw)

        if compact.startswith(f'{reg}[{inst}[2]]={self.const_var}[{inst}[3]]') or compact.startswith(f'{reg}[{inst}[2]]={inst}[3];'):
            return AtomicOp('LOADK', 'ABx', raw)

        if compact.startswith(f'{reg}[{inst}[2]]={reg}[{inst}[3]][') or (f'{reg}[{inst}[2]]={reg}[' in compact and '][' in compact):
            return AtomicOp('GETTABLE', 'ABC', raw)

        if compact.startswith(f'{reg}[{inst}[2]]={reg}[{inst}[3]];'):
            return AtomicOp('MOVE', 'ABC', raw)

        if '50' in compact and ('*50' in compact or '(C[5]-1)*50' in compact or 'F+C' in compact or 'e+C' in compact):
            return AtomicOp('SETLIST', 'ABC', raw)
        if 'V[C]=' in compact and 'E-o' in compact:
            return AtomicOp('SETLIST', 'ABC', raw)

        if 'V[C-o]' in compact or ('N-1' in compact and 'J=V[' in compact):
            return AtomicOp('VARARG', 'ABC', raw)

        if f'{reg}[{inst}[2]]=#' in compact:
            return AtomicOp('LEN', 'ABC', raw)
        if f'{reg}[{inst}[2]]=not' in compact:
            return AtomicOp('NOT', 'ABC', raw)
        if f'{reg}[{inst}[2]]=-{reg}[' in compact:
            return AtomicOp('UNM', 'ABC', raw)

        if '(F(' in compact or '(f(' in compact or '()};' in compact or '();' in compact or f'{reg}[D](F(' in compact:
            return AtomicOp('CALL', 'ABC', raw)

        return AtomicOp('UNKNOWN', 'RAW', raw)

    def resolve_opcode(self, op_val: int) -> List[AtomicOp]:
        if op_val in self.op_mappings:
            return self.op_mappings[op_val]

        raw = self.get_handler_code(op_val)
        if not raw:
            op = AtomicOp('NOP', 'RAW', '')
            self.op_mappings[op_val] = [op]
            return [op]

        delim = re.compile(rf'{self.pc_var}\s*=\s*{self.pc_var}\s*\+\s*1\s*;\s*{self.inst_var}\s*=\s*[a-zA-Z_]\w*\[{self.pc_var}\]\s*;')
        parts = delim.split(raw)

        ops = []
        for part in parts:
            part_str = part.strip()
            part_clean = re.sub(rf';?\s*{self.pc_var}={self.pc_var}\+1;?\s*$', '', part_str)
            if part_clean:
                ops.append(self.classify_atomic(part_clean))

        if not ops:
            ops = [AtomicOp('NOP', 'RAW', raw)]

        self.op_mappings[op_val] = ops
        return ops

class IRInstruction:
    def __init__(self, pc: int, op: str, a: Any = None, b: Any = None, c: Any = None,
                 target_pc: Optional[int] = None, orig_op: int = 0, raw_inst: Optional[List] = None):
        self.pc = pc
        self.op = op
        self.a = a
        self.b = b
        self.c = c
        self.target_pc = target_pc
        self.orig_op = orig_op
        self.raw_inst = raw_inst or []
        self.is_jump_target = False
        self.label: Optional[str] = None

    def __repr__(self):
        parts = [f"[{self.pc:4d}] {self.op:<10}"]
        if self.a is not None:
            parts.append(f"A={self.a}")
        if self.b is not None:
            parts.append(f"B={self.b!r}")
        if self.c is not None:
            parts.append(f"C={self.c!r}")
        if self.target_pc is not None:
            parts.append(f"-> L{self.target_pc}")
        return " ".join(parts)

def lift_proto(proto: Dict[str, Any], vm_analyzer: Any) -> Dict[str, Any]:
    consts = proto.get("consts", {})
    num_params = proto.get("num_params", 0)
    variant = proto.get("variant", 2)
    raw_instructions = proto.get("instructions", {})

    ir_instructions: List[IRInstruction] = []
    raw_to_ir_map: Dict[int, int] = {}

    inst_indices = sorted(raw_instructions.keys())
    i = 0
    while i < len(inst_indices):
        idx = inst_indices[i]
        raw = raw_instructions[idx]
        opcode = raw[0]

        resolved_ops = vm_analyzer.resolve_opcode(opcode)
        num_consumed = len(resolved_ops)
        extra_consumed = 0

        for step, atomic in enumerate(resolved_ops):
            curr_raw_idx = idx + step
            curr_raw = raw_instructions.get(curr_raw_idx, raw)

            ir_pc = len(ir_instructions) + 1
            raw_to_ir_map[curr_raw_idx] = ir_pc

            op_name = atomic.op_name
            A = curr_raw[1]
            B = curr_raw[2]
            C = curr_raw[4] if len(curr_raw) > 4 else curr_raw[3]

            if op_name in ('GETUPVAL', 'SETUPVAL'):
                ir_inst = IRInstruction(ir_pc, op_name, a=A, b=B, orig_op=opcode, raw_inst=curr_raw)

            elif op_name in ('GETGLOBAL', 'SETGLOBAL'):
                if isinstance(B, int) and B in consts:
                    B_val = consts[B]
                else:
                    B_val = B
                ir_inst = IRInstruction(ir_pc, op_name, a=A, b=B_val, orig_op=opcode, raw_inst=curr_raw)

            elif op_name == 'LOADK':
                if isinstance(B, int) and B in consts:
                    B_val = consts[B]
                else:
                    B_val = B
                ir_inst = IRInstruction(ir_pc, op_name, a=A, b=B_val, orig_op=opcode, raw_inst=curr_raw)

            elif op_name in ('GETTABLE', 'SETTABLE', 'SELF'):
                if isinstance(C, int) and C in consts:
                    C_val = consts[C]
                else:
                    C_val = C
                if op_name == 'SETTABLE' and isinstance(B, int) and B in consts:
                    B_val = consts[B]
                else:
                    B_val = B
                ir_inst = IRInstruction(ir_pc, op_name, a=A, b=B_val, c=C_val, orig_op=opcode, raw_inst=curr_raw)

            elif op_name in ('ADD', 'SUB', 'MUL', 'DIV', 'MOD', 'POW'):
                B_val = consts[B] if isinstance(B, int) and B in consts else B
                C_val = consts[C] if isinstance(C, int) and C in consts else C
                ir_inst = IRInstruction(ir_pc, op_name, a=A, b=B_val, c=C_val, orig_op=opcode, raw_inst=curr_raw)

            elif op_name == 'JMP':
                if variant == 1:
                    raw_target = (B + 1) if isinstance(B, (int, float)) else curr_raw_idx + 1
                else:
                    raw_target = curr_raw_idx + 1 + (B if isinstance(B, (int, float)) else 0)
                ir_inst = IRInstruction(ir_pc, op_name, a=A, b=B, target_pc=int(raw_target), orig_op=opcode, raw_inst=curr_raw)

            elif op_name in ('EQ', 'LT', 'LE', 'TEST'):
                if variant == 1:
                    raw_target = (B + 1) if isinstance(B, (int, float)) else curr_raw_idx + 1
                else:
                    raw_target = curr_raw_idx + 1 + (B if isinstance(B, (int, float)) else 1)
                C_val = consts[C] if isinstance(C, int) and C in consts else C
                ir_inst = IRInstruction(ir_pc, op_name, a=A, b=B, c=C_val, target_pc=int(raw_target), orig_op=opcode, raw_inst=curr_raw)

            elif op_name == 'CLOSURE':
                proto_idx = B if isinstance(B, int) else 0
                ir_inst = IRInstruction(ir_pc, op_name, a=A, b=proto_idx, orig_op=opcode, raw_inst=curr_raw)
                if variant == 2 and len(curr_raw) > 4 and isinstance(curr_raw[4], int) and curr_raw[4] > 0:
                    extra_consumed += curr_raw[4]

            elif op_name == 'FORLOOP':
                if variant == 1:
                    raw_target = (B + 1) if isinstance(B, (int, float)) else curr_raw_idx
                else:
                    raw_target = curr_raw_idx + 1 + (B if isinstance(B, (int, float)) else 0)
                ir_inst = IRInstruction(ir_pc, op_name, a=A, b=B, target_pc=int(raw_target), orig_op=opcode, raw_inst=curr_raw)

            else:
                ir_inst = IRInstruction(ir_pc, op_name, a=A, b=B, c=C, orig_op=opcode, raw_inst=curr_raw)

            ir_instructions.append(ir_inst)

        i += max(1, num_consumed) + extra_consumed

    for inst in ir_instructions:
        if inst.target_pc is not None:
            raw_tgt = inst.target_pc
            if raw_tgt in raw_to_ir_map:
                inst.target_pc = raw_to_ir_map[raw_tgt]
            elif raw_tgt > max(raw_to_ir_map.keys(), default=0):
                inst.target_pc = len(ir_instructions) + 1
            else:
                closest_raw = min(raw_to_ir_map.keys(), key=lambda r: abs(r - raw_tgt))
                inst.target_pc = raw_to_ir_map[closest_raw]

            if 1 <= inst.target_pc <= len(ir_instructions):
                ir_instructions[inst.target_pc - 1].is_jump_target = True

    lifted_protos = {}
    for p_idx, child in proto.get("protos", {}).items():
        lifted_protos[p_idx] = lift_proto(child, vm_analyzer)

    return {
        "variant": variant,
        "num_params": num_params,
        "consts": consts,
        "instructions": ir_instructions,
        "protos": lifted_protos
    }

def format_disassembly(lifted: Dict[str, Any], name: str = "main", depth: int = 0) -> str:
    indent = "  " * depth
    lines = [
        f"{indent}; ============================================================",
        f"{indent}; Function: {name} (params: {lifted.get('num_params', 0)}, instrs: {len(lifted.get('instructions', []))})",
        f"{indent}; ============================================================"
    ]

    consts = lifted.get("consts", {})
    if consts:
        lines.append(f"{indent}; Constants ({len(consts)}):")
        for k, v in sorted(consts.items(), key=lambda x: int(x[0])):
            lines.append(f"{indent};   [{k}] {v!r}")

    lines.append(f"{indent}; Instructions:")
    for inst in lifted.get("instructions", []):
        lbl = f"L{inst.pc}: " if inst.is_jump_target else "      "
        lines.append(f"{indent}{lbl}{inst}")

    for p_idx, child in lifted.get("protos", {}).items():
        lines.append("")
        lines.append(format_disassembly(child, f"{name}_proto_{p_idx}", depth + 1))

    return "\n".join(lines)

def is_valid_ident(s: Any) -> bool:
    if not isinstance(s, str):
        return False
    return bool(re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', s)) and s not in (
        'and', 'break', 'do', 'else', 'elseif', 'end', 'false', 'for',
        'function', 'if', 'in', 'local', 'nil', 'not', 'or', 'repeat',
        'return', 'then', 'true', 'until', 'while'
    )

def format_literal(v: Any) -> str:
    if v is None:
        return "nil"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        if isinstance(v, float) and v.is_integer():
            return str(int(v))
        return str(v)
    if isinstance(v, str):
        s = v.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
        clean = []
        for ch in s:
            code = ord(ch)
            if 32 <= code <= 126 or code > 127:
                clean.append(ch)
            else:
                clean.append(f'\\{code:03d}')
        return f'"{("".join(clean))}"'
    return str(v)

def invert_condition(cond: str) -> str:
    cond = cond.strip()
    if " == " in cond:
        return cond.replace(" == ", " ~= ", 1)
    if " ~= " in cond:
        return cond.replace(" ~= ", " == ", 1)
    if " <= " in cond:
        return cond.replace(" <= ", " > ", 1)
    if " >= " in cond:
        return cond.replace(" >= ", " < ", 1)
    if " < " in cond:
        return cond.replace(" < ", " >= ", 1)
    if " > " in cond:
        return cond.replace(" > ", " <= ", 1)
    if cond.startswith("not "):
        return cond[4:].strip()
    return f"not ({cond})"

class Decompiler:
    def __init__(self, lifted_proto: Dict[str, Any], func_name: str = "main", depth: int = 0):
        self.proto = lifted_proto
        self.func_name = func_name
        self.depth = depth
        self.instructions = lifted_proto.get("instructions", [])
        self.consts = lifted_proto.get("consts", {})
        self.child_protos = lifted_proto.get("protos", {})
        self.num_params = lifted_proto.get("num_params", 0)

        self.regs: Dict[int, str] = {}
        self.method_calls: Set[int] = set()
        self.lines: List[str] = []
        self.declared_locals: Set[int] = set()

    def _get_val(self, operand: Any) -> str:
        if isinstance(operand, str):
            if is_valid_ident(operand) or operand.startswith("(") or operand.startswith('"') or operand.startswith('{'):
                return operand
            return format_literal(operand)
        if isinstance(operand, (int, float, bool)) or operand is None:
            return format_literal(operand)
        return str(operand)

    def _reg_or_val(self, operand: Any) -> str:
        if isinstance(operand, int) and operand in self.regs:
            return self.regs[operand]
        return self._get_val(operand)

    def _emit(self, line: str):
        indent = "    " * self.depth
        self.lines.append(f"{indent}{line}")

    def decompile(self) -> str:
        for i in range(self.num_params):
            self.regs[i] = f"arg{i+1}"
            self.declared_locals.add(i)

        self._decompile_range(0, len(self.instructions))
        return "\n".join(self.lines)

    def _decompile_range(self, start_pc: int, end_pc: int):
        pc = start_pc
        while pc < end_pc and pc < len(self.instructions):
            inst = self.instructions[pc]
            op = inst.op
            A = inst.a
            B = inst.b
            C = inst.c
            target = inst.target_pc

            if op == 'GETUPVAL':
                self.regs[A] = f"upval_{B}"

            elif op == 'SETUPVAL':
                val = self.regs.get(A, f"v{A}")
                self._emit(f"upval_{B} = {val}")

            elif op == 'GETGLOBAL':
                self.regs[A] = str(B)

            elif op == 'SETGLOBAL':
                val = self.regs.get(A, f"v{A}")
                self._emit(f"{B} = {val}")

            elif op == 'LOADK':
                self.regs[A] = format_literal(B)

            elif op == 'LOADBOOL':
                self.regs[A] = "true" if B else "false"

            elif op == 'LOADNIL':
                s = A if isinstance(A, int) else 0
                e = B if isinstance(B, int) else s
                for r in range(s, e + 1):
                    self.regs[r] = "nil"

            elif op == 'MOVE':
                self.regs[A] = self.regs.get(B, f"v{B}")

            elif op == 'GETTABLE':
                obj = self.regs.get(B, f"v{B}")
                prop_val = self.regs.get(C, C) if isinstance(C, int) else C
                if isinstance(prop_val, str) and is_valid_ident(prop_val):
                    self.regs[A] = f"{obj}.{prop_val}"
                else:
                    prop_str = self._reg_or_val(C)
                    self.regs[A] = f"{obj}[{prop_str}]"

            elif op == 'SETTABLE':
                obj = self.regs.get(A, f"v{A}")
                if obj != "nil":
                    prop_val = self.regs.get(B, B) if isinstance(B, int) else B
                    val_str = self._reg_or_val(C)
                    if isinstance(prop_val, str) and is_valid_ident(prop_val):
                        self._emit(f"{obj}.{prop_val} = {val_str}")
                    else:
                        prop_str = self._reg_or_val(B)
                        self._emit(f"{obj}[{prop_str}] = {val_str}")

            elif op == 'NEWTABLE':
                self._emit(f"local v{A} = {{}}")
                self.regs[A] = f"v{A}"
                self.declared_locals.add(A)

            elif op == 'SELF':
                obj = self.regs.get(B, f"v{B}")
                self.regs[A + 1] = obj
                prop_val = self.regs.get(C, C) if isinstance(C, int) else C
                if isinstance(prop_val, str) and is_valid_ident(prop_val):
                    self.regs[A] = f"{obj}:{prop_val}"
                    self.method_calls.add(A)
                else:
                    self.regs[A] = f"{obj}[{format_literal(prop_val)}]"

            elif op in ('ADD', 'SUB', 'MUL', 'DIV', 'MOD', 'POW'):
                op_map = {'ADD': '+', 'SUB': '-', 'MUL': '*', 'DIV': '/', 'MOD': '%', 'POW': '^'}
                sym = op_map[op]
                b_str = self._reg_or_val(B)
                c_str = self._reg_or_val(C)
                self.regs[A] = f"({b_str} {sym} {c_str})"

            elif op == 'LEN':
                self.regs[A] = f"#{self.regs.get(B, f'v{B}')}"

            elif op == 'NOT':
                self.regs[A] = f"not ({self.regs.get(B, f'v{B}')})"

            elif op == 'UNM':
                self.regs[A] = f"-({self.regs.get(B, f'v{B}')})"

            elif op == 'CONCAT':
                start = B if isinstance(B, int) else A
                end = C if isinstance(C, int) else start
                parts = [self.regs.get(r, f"v{r}") for r in range(start, end + 1)]
                self.regs[A] = " .. ".join(parts)

            elif op == 'CLOSURE':
                proto_idx = B if isinstance(B, int) else 0
                func_ident = f"func_{proto_idx}"
                if proto_idx in self.child_protos:
                    child = self.child_protos[proto_idx]
                    child_dec = Decompiler(child, func_ident, self.depth + 1)
                    child_code = child_dec.decompile()
                    child_params = [f"arg{i+1}" for i in range(child.get("num_params", 0))]
                    indent = "    " * self.depth
                    self._emit(f"local {func_ident} = function({', '.join(child_params)})\n{child_code}\n{indent}end")
                    self.regs[A] = func_ident
                else:
                    self._emit(f"local {func_ident} = function() end")
                    self.regs[A] = func_ident

            elif op == 'CALL':
                fn = self.regs.get(A, f"v{A}")
                is_method = A in self.method_calls
                if is_method:
                    self.method_calls.remove(A)
                    if isinstance(B, int) and B >= A + 2:
                        args = [self.regs.get(r, f"v{r}") for r in range(A + 2, B + 1)]
                    elif isinstance(B, int) and B > 0:
                        num_args = max(0, B - 2)
                        args = [self.regs.get(A + 2 + i, f"v{A+2+i}") for i in range(num_args)]
                    else:
                        args = []
                else:
                    if isinstance(B, int) and B > A + 1:
                        args = [self.regs.get(r, f"v{r}") for r in range(A + 1, B + 1)]
                    elif isinstance(B, int) and B > 1:
                        num_args = max(0, B - 1)
                        args = [self.regs.get(A + 1 + i, f"v{A+1+i}") for i in range(num_args)]
                    else:
                        args = []

                call_expr = f"{fn}({', '.join(args)})"
                num_ret = C - 1 if isinstance(C, int) else 0

                if num_ret > 0:
                    self.regs[A] = call_expr
                else:
                    self._emit(call_expr)

            elif op == 'RETURN':
                num_ret = (B - 1) if isinstance(B, int) else 0
                if num_ret > 0:
                    ret_vals = [self.regs.get(A + i, f"v{A+i}") for i in range(num_ret)]
                    self._emit(f"return {', '.join(ret_vals)}")
                elif pc + 1 < end_pc:
                    self._emit("return")
                break

            elif op in ('EQ', 'LT', 'LE', 'TEST'):
                cond_raw = self._build_condition(op, A, B, C)
                cond_expr = invert_condition(cond_raw)
                
                next_inst = self.instructions[pc + 1] if pc + 1 < len(self.instructions) else None
                jump_target = target
                if next_inst and next_inst.op == 'JMP' and next_inst.target_pc is not None:
                    jump_target = next_inst.target_pc
                    pc += 1

                if jump_target is not None and jump_target > pc + 1:
                    then_end = min(jump_target - 1, end_pc)
                    
                    has_else = False
                    else_end = None
                    if then_end > pc + 1 and then_end - 1 < len(self.instructions):
                        last_inst = self.instructions[then_end - 1]
                        if last_inst.op == 'JMP' and last_inst.target_pc is not None and last_inst.target_pc > then_end:
                            has_else = True
                            else_end = min(last_inst.target_pc - 1, end_pc)
                            then_end -= 1

                    inner_dec = Decompiler(self.proto, self.func_name, self.depth + 1)
                    inner_dec.regs = dict(self.regs)
                    inner_dec._decompile_range(pc + 1, then_end)

                    else_lines = []
                    if has_else and else_end is not None:
                        else_dec = Decompiler(self.proto, self.func_name, self.depth + 1)
                        else_dec.regs = dict(self.regs)
                        else_dec._decompile_range(then_end + 1, else_end)
                        else_lines = else_dec.lines

                    if not inner_dec.lines and else_lines:
                        inv_cond = invert_condition(cond_expr)
                        self._emit(f"if {inv_cond} then")
                        self.lines.extend(else_lines)
                        self._emit("end")
                    elif inner_dec.lines:
                        self._emit(f"if {cond_expr} then")
                        self.lines.extend(inner_dec.lines)
                        if else_lines:
                            self._emit("else")
                            self.lines.extend(else_lines)
                        self._emit("end")

                    pc = else_end if (has_else and else_end is not None) else then_end
                    continue

            elif op == 'FORLOOP':
                pass

            elif op == 'JMP':
                pass

            pc += 1

    def _build_condition(self, op: str, A: Any, B: Any, C: Any) -> str:
        left = self.regs.get(A, f"v{A}")
        if isinstance(C, str):
            right = format_literal(C)
        elif isinstance(C, int) and C in self.regs:
            right = self.regs[C]
        else:
            right = format_literal(C) if C is not None else "nil"

        if op == 'EQ':
            return f"{left} == {right}"
        elif op == 'LT':
            return f"{left} < {right}"
        elif op == 'LE':
            return f"{left} <= {right}"
        elif op == 'TEST':
            return f"{left}"
        return f"{left}"

def decompile_proto(lifted_proto: Dict[str, Any], func_name: str = "main") -> str:
    decompiler = Decompiler(lifted_proto, func_name)
    body = decompiler.decompile()
    return body

def decompile(script_text: str) -> str:
    proto, meta = deserialize_script(script_text)
    analyzer = VMAnalyzer(script_text)
    lifted = lift_proto(proto, analyzer)
    return decompile_proto(lifted)

def decompile_file(input_path: str, output_path: Optional[str] = None) -> str:
    with open(input_path, 'r', encoding='utf-8', errors='replace') as f:
        code = f.read()

    result = decompile(code)

    if output_path:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(result)

    return result

def disassemble(script_text: str) -> str:
    proto, meta = deserialize_script(script_text)
    analyzer = VMAnalyzer(script_text)
    lifted = lift_proto(proto, analyzer)
    return format_disassembly(lifted)

def disassemble_file(input_path: str, output_path: Optional[str] = None) -> str:
    with open(input_path, 'r', encoding='utf-8', errors='replace') as f:
        code = f.read()

    result = disassemble(code)

    if output_path:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(result)

    return result

def main():
    parser = argparse.ArgumentParser(
        description="IronBrew 2 Full Decompiler Engine (Lua 5.1)"
    )
    parser.add_argument("input", help="Path to IronBrew 2 obfuscated Lua file")
    parser.add_argument("-o", "--output", help="Path to save decompiled Lua output", default=None)
    parser.add_argument("-d", "--disasm", action="store_true", help="Output IR bytecode disassembly instead of Lua source")

    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"Error: Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    t0 = time.time()
    if args.disasm:
        result = disassemble_file(args.input, args.output)
        mode_str = "Disassembled"
    else:
        result = decompile_file(args.input, args.output)
        mode_str = "Decompiled"

    elapsed = time.time() - t0

    if args.output:
        print(f"[+] {mode_str} '{args.input}' -> '{args.output}' in {elapsed:.2f}s")
    else:
        print(result)

if __name__ == "__main__":
    main()