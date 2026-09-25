const fs = require('fs');

function detect(source) {
  if (typeof source !== 'string') return false;
  return (
    source.includes('ironbrew1') ||
    (source.includes('ba([==[') && source.includes('local function d(n,v)')) ||
    (source.includes('local p=33;local y=85') && source.includes('bf[bi]=i[y]'))
  );
}

function decodeBase85(s) {
  const p = 33, y = 85, out = [];
  for (let bo = 0; bo < s.length; bo += 5) {
    let chunk = s.slice(bo, bo + 5);
    const bg = chunk.length;
    if (bg === 0) break;
    while (chunk.length < 5) chunk += 'u';
    const c0 = chunk.charCodeAt(0) - p;
    const c1 = chunk.charCodeAt(1) - p;
    const c2 = chunk.charCodeAt(2) - p;
    const c3 = chunk.charCodeAt(3) - p;
    const c4 = chunk.charCodeAt(4) - p;
    let val = ((((c0 * y + c1) * y + c2) * y + c3) * y + c4) >>> 0;
    const bytes = [(val >>> 24) & 255, (val >>> 16) & 255, (val >>> 8) & 255, val & 255];
    const len = bg < 5 ? bg - 1 : 4;
    for (let i = 0; i < len; i++) out.push(bytes[i]);
  }
  return out;
}

function decodeHuffman(y_bytes) {
  const bf_marker = Symbol(), bg_max = 256, bi_len = y_bytes.length;
  let bo_idx = 0, br_byte = 0, bs_bit = 256;
  function bv() {
    if (bs_bit > 128) {
      br_byte = bo_idx < bi_len ? y_bytes[bo_idx] : 0;
      bo_idx++;
      bs_bit = 1;
    }
    const bit = (bs_bit & br_byte) !== 0 ? 1 : 0;
    bs_bit *= 2;
    return bit;
  }
  function readExpGolomb() {
    let zeros = 0;
    while (bv() === 0) {
      zeros++;
      if (zeros > 32) return 1;
    }
    let br = 1;
    for (let bs = 0; bs < zeros; bs++) br = br * 2 + bv();
    return br;
  }
  const root = {};
  function insert(code, len, sym) {
    let node = root;
    for (let ca = len - 1; ca >= 0; ca--) {
      const bit = (code >>> ca) & 1;
      if (!node[bit]) node[bit] = {};
      node = node[bit];
    }
    node[bf_marker] = sym;
  }
  let v_total = 0;
  for (let br = 0; br < 32; br++) {
    if (bv() === 1) v_total += (2 ** br);
  }
  if (v_total === 0) return [];
  const v_count = readExpGolomb() - 1;
  const w_entries = [];
  for (let bw = 0; bw < v_count; bw++) {
    w_entries.push({ sym: readExpGolomb() - 1, len: readExpGolomb() });
  }
  w_entries.sort((a, b) => (a.len !== b.len ? a.len - b.len : a.sym - b.sym));
  let o_code = 0, v_prev_len = w_entries[0] ? w_entries[0].len : 0;
  for (let bw = 0; bw < w_entries.length; bw++) {
    const { sym, len } = w_entries[bw];
    if (len > v_prev_len) {
      o_code = (o_code << (len - v_prev_len)) >>> 0;
      v_prev_len = len;
    }
    insert(o_code, len, sym);
    o_code++;
  }
  function decodeSymbol() {
    let node = root;
    while (true) {
      node = node[bv()];
      if (!node) return null;
      if (node[bf_marker] !== undefined) return node[bf_marker];
    }
  }
  const out = [];
  let count = 0;
  while (count < v_total) {
    const sym = decodeSymbol();
    if (sym === null) break;
    if (sym === bg_max) {
      const repeatSym = decodeSymbol();
      if (repeatSym === null) break;
      const repCount = readExpGolomb();
      for (let bg = 0; bg < repCount; bg++) {
        out.push(repeatSym);
        count++;
      }
    } else {
      out.push(sym);
      count++;
    }
  }
  return out;
}

function decodeMTF(v_symbols) {
  const y_table = [];
  for (let bf = 0; bf < 256; bf++) y_table[bf] = bf;
  const out = new Uint8Array(v_symbols.length);
  for (let d = 0; d < v_symbols.length; d++) {
    const v_idx = v_symbols[d];
    const val = y_table[v_idx];
    out[d] = val;
    if (v_idx > 0) {
      for (let k = v_idx; k > 0; k--) y_table[k] = y_table[k - 1];
      y_table[0] = val;
    }
  }
  return out;
}

function decodeBWT(n_bytes, v_index) {
  const w = n_bytes.length;
  if (w === 0) return Buffer.alloc(0);
  let v = v_index;
  const counts = new Int32Array(256);
  for (let i = 0; i < w; i++) counts[n_bytes[i]]++;
  const base = new Int32Array(256);
  let cumulative = 0;
  for (let c = 0; c < 256; c++) {
    base[c] = cumulative;
    cumulative += counts[c];
  }
  const next_arr = new Int32Array(w);
  for (let i = 0; i < w; i++) {
    next_arr[base[n_bytes[i]]++] = i;
  }
  const out = Buffer.allocUnsafe(w);
  for (let i = 0; i < w; i++) {
    v = next_arr[v];
    out[i] = n_bytes[v];
  }
  return out;
}

function decompressIB1(rawBytes) {
  const i = rawBytes;
  const resultChunks = [];
  let v = 0;
  while (v + 7 < i.length) {
    const w = i[v] + i[v + 1] * 256 + i[v + 2] * 65536 + i[v + 3] * 16777216;
    v += 4;
    const y_len = i[v] + i[v + 1] * 256 + i[v + 2] * 65536 + i[v + 3] * 16777216;
    v += 4;
    if (v + y_len > i.length) break;
    const b_slice = i.slice(v, v + y_len);
    v += y_len;
    resultChunks.push(decodeBWT(decodeMTF(decodeHuffman(b_slice)), w));
  }
  return Buffer.concat(resultChunks);
}

class ByteReader {
  constructor(buf) {
    this.buf = buf;
    this.pos = 0;
  }
  readByte() {
    return this.buf[this.pos++];
  }
  readInt16() {
    const r = this.buf.readUInt16LE(this.pos);
    this.pos += 2;
    return r;
  }
  readInt32() {
    const r = this.buf.readUInt32LE(this.pos);
    this.pos += 4;
    return r;
  }
  readFloat64() {
    const r = this.buf.readDoubleLE(this.pos);
    this.pos += 8;
    return r;
  }
  readInt64() {
    const low = this.readInt32();
    let high = this.readInt32();
    if (high >= 2147483648) high -= 4294967296;
    return high * 4294967296 + low;
  }
  readVarInt() {
    let a = 0, b = 1;
    while (true) {
      const e = this.readByte();
      a += (e > 127 ? e - 128 : e) * b;
      b *= 128;
      if (e < 128) break;
    }
    return a;
  }
  readString(len) {
    const s = this.buf.slice(this.pos, this.pos + len).toString('utf8');
    this.pos += len;
    return s;
  }
}

function deserializeChunk(r) {
  const constCount = r.readVarInt();
  const constants = [];
  for (let i = 0; i < constCount; i++) {
    const t = r.readByte();
    if (t === 0) {
      r.readByte();
      const len = r.readVarInt();
      constants.push(r.readString(len));
    } else if (t === 1 || t === 2) {
      constants.push(r.readInt64());
    } else if (t === 3 || t === 4) {
      constants.push(r.readFloat64());
    } else if (t === 5) {
      constants.push(r.readByte() === 1);
    } else {
      constants.push(null);
    }
  }

  const instCount = r.readVarInt();
  const instructions = [];
  for (let i = 0; i < instCount; i++) {
    const op = r.readVarInt();
    const cb = r.readByte() === 1;
    const ce = r.readByte() === 1;
    const cf = r.readByte() === 1;
    const cg = r.readByte();
    let A, B, C;
    if (cg === 1) {
      const ch = r.readInt16();
      const arrA = [], arrB = [], arrC = [];
      for (let cn = 0; cn < ch; cn++) {
        arrA.push(r.readInt32());
        arrB.push(r.readInt32());
        arrC.push(r.readInt32());
        r.readInt32();
        r.readInt32();
      }
      A = arrA;
      B = arrB;
      C = arrC;
    } else if (cg === 2) {
      const ch = r.readInt16();
      const arrA = [], arrB = [];
      for (let ck = 0; ck < ch; ck++) {
        arrA.push(r.readInt32());
        arrB.push(r.readInt32());
      }
      A = arrA;
      B = arrB;
      C = 0;
    } else if (cg === 3) {
      const ch = r.readInt16();
      const arrA = [];
      for (let ci = 0; ci < ch; ci++) {
        arrA.push(r.readInt32());
      }
      A = arrA;
      B = 0;
      C = 0;
    } else {
      A = r.readInt32();
      B = r.readInt32();
      C = r.readInt32();
      r.readInt32();
      r.readInt32();
    }
    r.readInt32();
    r.readInt32();
    r.readInt32();
    r.readInt32();
    r.readInt32();
    instructions.push({ op, A, B, C, typeA: cb, typeB: ce, typeC: cf });
  }

  const bz = r.readByte() !== 0;
  if (bz) {
    const lineCount = r.readVarInt();
    for (let ce = 1; ce <= lineCount; ce++) {
      r.readByte();
      r.readInt32();
    }
  }
  const upvalCount = r.readVarInt();
  const upvalues = [];
  for (let ce = 1; ce <= upvalCount; ce++) {
    upvalues.push({ isLocal: r.readByte() !== 0, reg: r.readInt32() });
  }
  const numParams = r.readByte();
  const isVararg = r.readByte() === 1;
  const maxStackSize = r.readVarInt();
  const protoCount = r.readVarInt();
  const protos = [];
  for (let bv = 0; bv < protoCount; bv++) {
    protos.push(deserializeChunk(r));
  }
  return { constants, instructions, upvalues, numParams, isVararg, maxStackSize, protos };
}

function extractRootChunk(source) {
  const start = source.indexOf('ba([==[');
  if (start === -1) throw new Error('IronBrew1 payload ba([==[ not found');
  const end = source.indexOf(']==])', start);
  if (end === -1) throw new Error('IronBrew1 payload end ]==]) not found');
  const payload = source.slice(start + 7, end);

  const rawBytes = decodeBase85(payload);
  const decompressed = decompressIB1(rawBytes);
  const reader = new ByteReader(decompressed);
  return deserializeChunk(reader);
}

function extractStringsDynamically(chunk) {
  const K = chunk.constants;
  const insts = chunk.instructions;
  if (!insts || insts.length === 0) return { xorKey: 0, strMap: {} };

  let xorKey = 0;
  for (let i = 0; i < Math.min(30, insts.length); i++) {
    const ins = insts[i];
    if (ins.op === 13 && ins.A === 0 && typeof K[ins.B] === 'number') {
      xorKey = K[ins.B];
      break;
    }
  }

  const strMap = {};
  for (let i = 0; i < Math.min(120, insts.length); i++) {
    const ins = insts[i];
    if (ins.op === 17 && ins.A === 7 && ins.B === 2) {
      if (typeof K[8] === 'number' && typeof K[9] === 'number') {
        const text = String.fromCharCode(K[8] ^ xorKey) + String.fromCharCode(K[9] ^ xorKey);
        strMap[1] = text;
      }
    } else if (ins.op === 45 && Array.isArray(ins.A) && Array.isArray(ins.B) && ins.A.length > 0) {
      const targetReg = ins.A[0] - 1;
      const strIdx = targetReg - 6;
      if (strIdx >= 1) {
        const text = ins.B.map((b) => String.fromCharCode(K[b] ^ xorKey)).join('');
        strMap[strIdx] = text;
      }
    }
  }

  return { xorKey, strMap };
}

module.exports = {
  detect,
  decodeBase85,
  decompressIB1,
  deserializeChunk,
  extractRootChunk,
  extractStringsDynamically,
};