import re, os, json, sys
sys.setrecursionlimit(20000)


def xo(a, b):
    a &= 255; b &= 255
    r = 0; m = 1
    for _ in range(8):
        if (a & 1) != (b & 1): r |= m
        a >>= 1; b >>= 1; m <<= 1
    return r


def sg(x):
    return x if x < 128 else x - 256


def idn(l):
    return len(l) - len(l.lstrip())


def ss(l):
    o = []
    i = 0
    n = len(l)
    while i < n:
        c = l[i]
        if c in ('"', "'"):
            q = c
            i += 1
            while i < n:
                if l[i] == '\\':
                    i += 2
                    continue
                if l[i] == q:
                    i += 1
                    break
                i += 1
            o.append('""')
            continue
        o.append(c)
        i += 1
    return ''.join(o)


def sv(ln, fn):
    o = []
    i = 0
    n = len(ln)
    while i < n:
        c = ln[i]
        if c in ('"', "'"):
            q = c
            o.append(c)
            i += 1
            while i < n:
                if ln[i] == '\\':
                    o.append(ln[i:i + 2])
                    i += 2
                    continue
                o.append(ln[i])
                if ln[i] == q:
                    i += 1
                    break
                i += 1
            continue
        if c == 'v' and i + 1 < n and ln[i + 1].isdigit():
            j = i + 1
            while j < n and ln[j].isdigit():
                j += 1
            pv = (i == 0) or not (ln[i - 1].isalnum() or ln[i - 1] == '_')
            nx = (j >= n) or not (ln[j].isalnum() or ln[j] == '_')
            if pv and nx:
                o.append(fn(ln[i:j]))
                i = j
                continue
        o.append(c)
        i += 1
    return ''.join(o)


def br(s, n):
    m = re.search(r'(?:local\s+)?\b' + re.escape(n) + r'\b\s*=\s*\{', s)
    if not m: return None
    i = m.end() - 1; d = 0; q = None; p = i
    while i < len(s):
        c = s[i]
        if q:
            if c == '\\': i += 2; continue
            if c == q: q = None
        else:
            if c == '"' or c == "'": q = c
            elif c == '{': d += 1
            elif c == '}':
                d -= 1
                if d == 0: return s[p:i + 1]
        i += 1
    return None


def ar(s):
    if not s: return None
    try:
        return json.loads(s.replace('{', '[').replace('}', ']'))
    except Exception:
        return None


def iv(s, n):
    m = re.search(r'local\s+' + re.escape(n) + r'\s*=\s*\(', s)
    if not m: return None
    r = s[m.end() - 1:]; d = 0; i = 0
    while i < len(r):
        c = r[i]
        if c == '(': d += 1
        elif c == ')':
            d -= 1
            if d == 0: break
        i += 1
    if d: return None
    try:
        return int(eval(r[:i + 1])) % 256
    except Exception:
        return None


def gv(s, n, d=0):
    if d > 10: return None
    m = re.search(r'local\s+' + re.escape(n) + r'\s*=\s*(\d+)\b', s)
    if m: return int(m.group(1)) % 256
    v = iv(s, n)
    if v is not None: return v
    m = re.search(r'local\s+' + re.escape(n) + r'\s*=\s*(\w+)\b', s)
    if m and m.group(1) != n: return gv(s, m.group(1), d + 1)
    return None


BP = {6: '+', 7: '-', 8: '*', 9: '/', 10: '%', 11: '^', 12: '..',
      16: '==', 17: '<', 18: '<='}


def fb(src):
    res = []
    for m in re.finditer(
        r'for\s+(\w+)\s*=\s*1\s*,\s*#(\w+)\s+do\s+'
        r'local\s+(\w+)\s*=\s*\w+\(\s*\2\s*\[\s*\1\s*\]\s*,\s*(\w+)\s*\)\s*'
        r'(\w+)\[\1\]=\3\s*'
        r'\4=\(\4\+\3\+(\w+)\)%256',
        src):
        res.append((m.group(2), m.group(4), m.group(6)))
    for m in re.finditer(
        r'while\s+(\w+)\s*<=\s*#(\w+)\s+do\s+'
        r'local\s+(\w+)\s*=\s*\w+\(\s*\2\s*\[\s*\1\s*\]\s*,\s*(\w+)\s*\)\s*'
        r'(\w+)\[\1\]=\3\s*'
        r'\4=\(\4\+\3\+(\w+)\)%256\s*'
        r'\1\s*=\s*\1\s*\+\s*1',
        src):
        res.append((m.group(2), m.group(4), m.group(6)))
    return res


class Rd:
    __slots__ = ('bf', 'ps')
    def __init__(self, bf): self.bf = bf; self.ps = 0
    def g1(self):
        if self.ps >= len(self.bf): raise IndexError
        v = self.bf[self.ps]; self.ps += 1; return v
    def g2(self): return (self.g1() << 8) | self.g1()
    def g4(self):
        v = (self.g1() << 24) | (self.g1() << 16) | (self.g1() << 8) | self.g1()
        if v >= 0x80000000: v -= 0x100000000
        return v


def ppo(dc, ly):
    r = Rd(dc)
    try:
        np = r.g2()
        if np <= 0 or np > 100000: return None, r.ps
        ps = [None]
        for _ in range(np):
            nc = r.g2()
            if ly == 'v012':
                oa = [r.g1() for _ in range(nc)]
                kb = [r.g1() for _ in range(nc)]
                oa = [(oa[i] ^ kb[i]) & 0xFF for i in range(nc)]
                aa = [r.g1() for _ in range(nc)]
                ba = [r.g1() for _ in range(nc)]
                ca = [r.g1() for _ in range(nc)]
                od = [r.g1() for _ in range(nc)]
            elif ly == 'v007c':
                oa = [r.g1() for _ in range(nc)]
                kb = [r.g1() for _ in range(nc)]
                oa = [(oa[i] ^ kb[i]) & 0xFF for i in range(nc)]
                aa = [r.g1() for _ in range(nc)]
                ba = [r.g1() for _ in range(nc)]
                ca = [r.g1() for _ in range(nc)]
                od = None
            elif ly == 'v006c':
                oa = [r.g1() for _ in range(nc)]
                aa = [r.g1() for _ in range(nc)]
                ba = [r.g1() for _ in range(nc)]
                ca = [r.g1() for _ in range(nc)]
                od = None
            else:
                cd = [r.g1() for _ in range(nc)]
                if len(cd) % 4 != 0: return None, r.ps
                oa = cd[0::4]; aa = cd[1::4]; ba = cd[2::4]; ca = cd[3::4]
                od = None
            nk = r.g2()
            cs = [None]
            for _ in range(nk):
                tg = r.g1()
                if tg == 1: cs.append(-r.g2())
                elif tg == 2: cs.append(r.g4())
                else: cs.append(0)
            pm = r.g2(); va = r.g1(); nn = r.g2()
            nt = [r.g2() for _ in range(nn)]
            ps.append({'ops': oa, 'as': aa, 'bs': ba, 'cs': ca, 'ord': od,
                       'consts': cs, 'pm': pm, 'va': va, 'nest': nt,
                       'nc': len(oa), 'nk': nk})
        return ps, r.ps
    except IndexError:
        return None, r.ps


def od(s):
    v012 = re.search(
        r'\w+\[\w+\]\s*=\s*\{\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*\w+\s*\}',
        s) is not None

    v_st = None
    for mm in re.finditer(r'local\s+(\w+)\s*=\s*\{', s):
        nm = mm.group(1)
        raw = br(s, nm)
        if not raw: continue
        arr = ar(raw)
        if not arr or not isinstance(arr, list) or not arr: continue
        if not all(isinstance(x, list) and
                   all(isinstance(y, int) and 0 <= y <= 255 for y in x)
                   for x in arr): continue
        if len(arr) > 200: continue
        v_st = arr
        break

    v_key = None
    v_tag = None
    if v_st is not None and not v012:
        m = re.search(r'\((\w+)\[(\w+)\]~(\w+)\)%256', s)
        if m:
            v_key = gv(s, m.group(3))
            if v_key is not None:
                v_tag = 'v001'
        if v_key is None:
            m = re.search(
                r'for\s+\w+\s*=\s*1\s*,\s*#(\w+)\s+do\s+'
                r'\w+\[\w+\]\s*=\s*\w+\(\s*\w+\(\s*\1\[\w+\]\s*,\s*(\w+)\s*\)',
                s)
            if m:
                v_key = gv(s, m.group(2))
                if v_key is not None:
                    v_tag = 'v003'

    m_om = re.search(r'(\w+)\s*=\s*(\w+)\[(\w+)\]\s*or\s*\3', s)
    om = None
    if m_om:
        ot = ar(br(s, m_om.group(2)))
        if ot:
            om = ot

    ps = None
    ly = None
    cr = None
    tu = None
    cP = None
    cPm = None
    si = None; mu = None; ssc = None; st = None

    if v012:
        ms = list(re.finditer(
            r'xg\(\s*(\w+)\s*\[\s*\w+\s*\]\s*or\s*0\s*,\s*xg\(\s*(\w+)\s*,',
            s))
        GI89 = None; zU = None
        if len(ms) >= 1:
            GI89 = ar(br(s, ms[0].group(1)))
            zU = gv(s, ms[0].group(2))
        if len(ms) >= 2:
            cP = ar(br(s, ms[1].group(1)))
            cPm = gv(s, ms[1].group(2))

        if GI89 and zU is not None:
            L = len(GI89)
            tu = [0] * 256
            for z in range(256):
                a = GI89[z - 1] if 1 <= z <= L else 0
                tu[z] = (a ^ (zU ^ z)) & 0xFF

        m_si = re.search(
            r'local\s+(\w+)\s*=\s*\(\s*(\w+)\s*\+\s*\(\s*\w+\s*-\s*1\s*\)\s*\*\s*(\w+)\s*\)\s*%\s*256',
            s)
        if m_si:
            sv_ = m_si.group(2); mv = m_si.group(3)
            si = gv(s, sv_)
            mu = int(mv) % 256 if mv.isdigit() else gv(s, mv)
            ck = s[m_si.end():m_si.end() + 400]
            m3 = re.search(re.escape(m_si.group(1)) + r'\s*=\s*\(\s*'
                           + re.escape(m_si.group(1))
                           + r'\s*\+\s*\w+\s*\+\s*(\w+)\s*\)\s*%\s*256',
                           ck)
            if m3: ssc = gv(s, m3.group(1))

        btl = fb(s)
        if len(btl) >= 2:
            inf = []
            for name, ivn, svn in btl:
                arr = ar(br(s, name))
                if not arr: continue
                ini = gv(s, ivn); stp = gv(s, svn)
                if ini is None or stp is None: continue
                inf.append((name, arr, ini, stp))
            if len(inf) < 2:
                return None, None
            inf.sort(key=lambda x: -len(x[1]))
            big, sm = inf[0], inf[1]
            k = sm[2]; dc0 = []
            for x in sm[1]:
                y = xo(x, k); dc0.append(y)
                k = (k + y + sm[3]) & 0xFF
            pos = [0]
            def rd_():
                v = dc0[pos[0]] if pos[0] < len(dc0) else 0
                pos[0] += 1
                return v
            def rd2_(): return (rd_() << 8) | rd_()
            ns = rd2_()
            st = []
            for _ in range(ns):
                ln = rd2_()
                st.append([rd_() for _ in range(ln)])
            k = big[2]; dc = []
            for x in big[1]:
                y = xo(x, k); dc.append(y)
                k = (k + y + big[3]) & 0xFF
            pr, en = ppo(dc, 'v012')
            if pr is None:
                return None, None
            ps = pr; ly = 'v012'
        else:
            return None, None

        _si = si; _mu = mu; _ss = ssc; _st = st
        def cr(i):
            kk = (_si + (i - 1) * _mu) & 255
            a = _st[i - 1]; o = []
            for v in a:
                d = xo(v, kk); o.append(chr(d))
                kk = (kk + d + _ss) & 255
            return ''.join(o)

    if ps is None and v_tag is not None:
        mm = re.search(
            r'return\s+(\w+)\s*\(\s*(\w+)\s*\[\s*1\s*\]\s*,\s*\{\}\s*,', s)
        if mm:
            pt = ar(br(s, mm.group(2)))
            if (pt and isinstance(pt, list) and len(pt) >= 1
                    and isinstance(pt[0], list)):
                ly = v_tag
                ps = [None]
                for p in pt:
                    code = p[0] if p else []
                    oa = code[0::4]; aa = code[1::4]
                    ba = code[2::4]; ca = code[3::4]
                    rcs = p[1] if len(p) > 1 and p[1] else []
                    cpy = [None] + list(rcs)
                    ps.append({'ops': oa, 'as': aa, 'bs': ba, 'cs': ca,
                               'ord': None, 'consts': cpy,
                               'pm': p[2] if len(p) > 2 else 0,
                               'va': p[3] if len(p) > 3 else 0,
                               'nest': p[4] if len(p) > 4 else [],
                               'nc': len(oa)})
                _k = v_key
                _st = v_st
                def cr(i):
                    a = _st[i - 1]
                    return ''.join(chr((v ^ _k) & 0xFF) for v in a)

    if ps is None and not v012:
        m = re.search(
            r'local\s+(\w+)\s*=\s*\(\s*(\w+)\s*\+\s*\(\s*\w+\s*-\s*1\s*\)\s*\*\s*(\w+)\s*\)\s*%\s*256',
            s)
        if m:
            sv_ = m.group(2); mv = m.group(3)
            si = gv(s, sv_)
            mu = int(mv) % 256 if mv.isdigit() else gv(s, mv)
            ck = s[m.end():m.end() + 400]
            m3 = re.search(re.escape(m.group(1)) + r'\s*=\s*\(\s*'
                           + re.escape(m.group(1))
                           + r'\s*\+\s*\w+\s*\+\s*(\w+)\s*\)\s*%\s*256',
                           ck)
            if m3: ssc = gv(s, m3.group(1))
            m2 = re.search(r'=\s*(\w+)\s*\[\s*\w+\s*\]', ck)
            if m2: st = ar(br(s, m2.group(1)))

        m_tu = re.search(
            r'(\w+)\s*\[\s*(\w+)\s*\]\s*or\s*\2\s*,\s*\w+\s*\(\s*(\w+)\s*,\s*\2\s*%\s*256',
            s)
        if m_tu:
            ta = ar(br(s, m_tu.group(1)))
            tv = gv(s, m_tu.group(3))
            if ta and tv is not None:
                tu = [0] * 256
                for z in range(256):
                    a = ta[z - 1] if 1 <= z <= len(ta) else z
                    bb = (tv ^ z) & 0xFF
                    tu[z] = (a ^ bb) & 0xFF

        mm = re.search(
            r'return\s+(\w+)\s*\(\s*(\w+)\s*\[\s*1\s*\]\s*,\s*\{\}\s*,', s)
        if mm:
            pt = ar(br(s, mm.group(2)))
            if (pt and isinstance(pt, list) and len(pt) > 3
                    and isinstance(pt[0], list)):
                ly = 'v004'
                ps = [None]
                for p in pt:
                    code = p[0] if p else []
                    oa = code[0::4]; aa = code[1::4]
                    ba = code[2::4]; ca = code[3::4]
                    rcs = p[1] if len(p) > 1 and p[1] else []
                    cpy = [None] + list(rcs)
                    ps.append({'ops': oa, 'as': aa, 'bs': ba, 'cs': ca,
                               'ord': None, 'consts': cpy,
                               'pm': p[2] if len(p) > 2 else 0,
                               'va': p[3] if len(p) > 3 else 0,
                               'nest': p[4] if len(p) > 4 else [],
                               'nc': len(oa)})

        if ps is None:
            btl = fb(s)

            if len(btl) >= 2:
                inf = []
                for name, ivn, svn in btl:
                    arr = ar(br(s, name))
                    if not arr: continue
                    ini = gv(s, ivn); stp = gv(s, svn)
                    if ini is None or stp is None: continue
                    inf.append((name, arr, ini, stp))
                if len(inf) < 2:
                    return None, None
                inf.sort(key=lambda x: -len(x[1]))
                big, sm = inf[0], inf[1]
                k = sm[2]; dc0 = []
                for x in sm[1]:
                    y = xo(x, k); dc0.append(y)
                    k = (k + y + sm[3]) & 0xFF
                pos = [0]
                def rd_():
                    v = dc0[pos[0]] if pos[0] < len(dc0) else 0
                    pos[0] += 1
                    return v
                def rd2_(): return (rd_() << 8) | rd_()
                ns = rd2_()
                st = []
                for _ in range(ns):
                    ln = rd2_()
                    st.append([rd_() for _ in range(ln)])
                k = big[2]; dc = []
                for x in big[1]:
                    y = xo(x, k); dc.append(y)
                    k = (k + y + big[3]) & 0xFF
                pr, en = ppo(dc, 'v007c')
                if pr is None:
                    return None, None
                ps = pr; ly = 'v008'

                m_vf = re.search(
                    r'local\s+(\w+)\s*=\s*\{[\d,]+\}\s*'
                    r'local\s+\1m\s*=\s*(\d+)\s*'
                    r'local\s+\1ok\s*=\s*(\d+)\s*'
                    r'local\s+\1ak\s*=\s*(\d+)\s*'
                    r'local\s+\1bk\s*=\s*(\d+)\s*'
                    r'local\s+\1ck\s*=\s*(\d+)', s)
                if m_vf:
                    vf = ar(br(s, m_vf.group(1)))
                    if vf:
                        vm = int(m_vf.group(2)); vo = int(m_vf.group(3))
                        va = int(m_vf.group(4)); vb = int(m_vf.group(5))
                        vc = int(m_vf.group(6))
                        L = len(vf)
                        for p in ps[1:]:
                            nc = p['nc']
                            no = [0]*nc; na = [0]*nc; nb = [0]*nc; ncc = [0]*nc
                            for j in range(nc):
                                old = p['ops'][j]
                                v = vf[old-1] if 1 <= old <= L else 0
                                no[j] = (v ^ (vm ^ old)) & 0xFF
                                idx = j + 1
                                em_ = ((idx*13) + vo) & 0xFF
                                na[j] = (p['as'][j] ^ (va ^ em_)) & 0xFF
                                nb[j] = (p['bs'][j] ^ (vb ^ em_)) & 0xFF
                                ncc[j] = (p['cs'][j] ^ (vc ^ em_)) & 0xFF
                            p['ops'] = no; p['as'] = na; p['bs'] = nb; p['cs'] = ncc
                        ly = 'v009'

            elif len(btl) == 1:
                name, ivn, svn = btl[0]
                bt = ar(br(s, name))
                if not bt:
                    return None, None
                bi = gv(s, ivn); bs = gv(s, svn)
                k = bi; q = bs; dc = []
                for x in bt:
                    y = xo(x, k); dc.append(y); k = (k + y + q) & 255
                cd = []
                for lyt in ('v007c', 'v006c', 'v005'):
                    pr, en = ppo(dc, lyt)
                    if pr is not None: cd.append((lyt, pr, en))
                ch = None
                for lyt, pr, en in cd:
                    if en == len(dc): ch = (lyt, pr); break
                if ch is None and cd:
                    cd.sort(key=lambda x: abs(x[2] - len(dc)))
                    ch = (cd[0][0], cd[0][1])
                if ch is None:
                    return None, None
                ly, ps = ch
            else:
                return None, None

        _si = si; _mu = mu; _ss = ssc; _st = st
        def cr(i):
            kk = (_si + (i - 1) * _mu) & 255
            a = _st[i - 1]; o = []
            for v in a:
                d = xo(v, kk); o.append(chr(d))
                kk = (kk + d + _ss) & 255
            return ''.join(o)

    if ps is None:
        return None, None

    def lk(p, i):
        cs = p['consts']
        if i < 0 or i >= len(cs): return None
        v = cs[i]
        if v is None: return None
        if isinstance(v, int) and v < 0: return cr(-v)
        return v

    def lt(v):
        if v is None: return "nil"
        if isinstance(v, bool): return "true" if v else "false"
        if isinstance(v, str):
            e = v.replace('\\', '\\\\').replace("'", "\\'")
            e = (e.replace('\n', '\\n').replace('\r', '\\r')
                 .replace('\t', '\\t'))
            return "'" + e + "'"
        return str(v)

    ir = re.compile(r'^[A-Za-z_]\w*$')
    sc = [0]; us = set()

    def dec(p, d0, st0=None):
        n = p['nc']
        ops = []
        if ly == 'v012':
            od_ = p.get('ord') or []
            remap = {37: 1, 32: 22, 42: 23, 31: 29, 33: 35}
            for i in range(n):
                akph = i + 1
                if i < len(od_) and od_[i] >= 1:
                    akph = od_[i]
                idx = akph - 1
                if idx < 0 or idx >= n:
                    idx = i
                raw = p['ops'][idx]
                inter = tu[raw] if (tu and 0 <= raw < 256) else 0
                if 1 <= inter <= 40 and cP:
                    final = cP[inter - 1] ^ (cPm ^ (inter & 0xFF))
                else:
                    final = 0
                final = remap.get(final, 0)
                ops.append((final, p['as'][idx], p['bs'][idx], p['cs'][idx]))
        else:
            for i in range(n):
                R = p['ops'][i]
                if om and 1 <= R <= len(om): R = om[R - 1]
                if tu is not None: R = tu[R & 0xFF]
                ops.append((R, p['as'][i], p['bs'][i], p['cs'][i]))

        out = []

        def sy(t, r):
            if r in t and t[r] is not None: return t[r]
            return "v%d" % r

        def sr(t, r, v):
            rv = "v%d" % r
            for kk in [k for k, vv in t.items() if vv == rv and k != r]:
                t[kk] = None
            t[r] = v

        def em(i0, j0, dd, t):
            pr = "  " * dd; i = i0
            while i < j0:
                R, a, b, c = ops[i]

                if R == 22 and b >= 1 and c >= 3 and i + 1 < j0:
                    S, x, y, z = ops[i + 1]
                    if S in (20, 21) and y == a:
                        tg = i + 1 + sg(x)
                        if tg > j0: tg = j0
                        if tg > i + 2:
                            fj = -1
                            for j in range(i + 2, tg):
                                Sj, xj, _, _ = ops[j]
                                if Sj == 19 and j + sg(xj) == i:
                                    fj = j; break
                            if fj > 0:
                                nv = c - 2
                                if nv >= 1:
                                    ie = sy(t, a); se = sy(t, a + 1)
                                    ce_ = sy(t, a + 2)
                                    vs = ["v%d" % (a + j)
                                          for j in range(nv)]
                                    for kk in range(nv + 2):
                                        t.pop(a + kk, None)
                                    out.append(
                                        pr + "for %s in %s, %s, %s do" % (
                                            ", ".join(vs), ie, se, ce_))
                                    em(i + 2, fj, dd + 1, t)
                                    out.append(pr + "end")
                                    i = tg; continue

                if R == 19:
                    i = i + sg(a); continue

                if R == 20 or R == 21:
                    tg = i + sg(a)
                    if tg > j0: tg = j0
                    el = None
                    if tg - 1 > i and tg - 1 < j0:
                        p2, q2, _, _ = ops[tg - 1]
                        if p2 == 19:
                            el = tg - 1 + sg(q2)
                            if el > j0: el = j0
                    cd = sy(t, b)
                    if el is not None:
                        if R == 21:
                            out.append(pr + "if " + cd + " then")
                            em(i + 1, tg - 1, dd + 1, dict(t))
                            out.append(pr + "else")
                            em(tg, el, dd + 1, dict(t))
                            out.append(pr + "end")
                        else:
                            out.append(pr + "if not " + cd + " then")
                            em(i + 1, tg - 1, dd + 1, dict(t))
                            out.append(pr + "else")
                            em(tg, el, dd + 1, dict(t))
                            out.append(pr + "end")
                        i = el
                    else:
                        if R == 21: out.append(pr + "if " + cd + " then")
                        else:       out.append(pr + "if not " + cd + " then")
                        em(i + 1, tg, dd + 1, dict(t))
                        out.append(pr + "end")
                        i = tg
                    t.clear(); continue

                if R == 1:
                    sb = t.get(b)
                    if sb is None: sb = "v%d" % b
                    sr(t, a, sb)
                elif R == 2 or R == 31:
                    kv = lk(p, b)
                    if isinstance(kv, str): sr(t, a, lt(kv))
                    else:
                        out.append(pr + "v%d = %s" % (a, lt(kv)))
                        sr(t, a, "v%d" % a)
                elif R == 3: sr(t, a, "nil")
                elif R == 4: sr(t, a, "true" if b else "false")
                elif R == 5:
                    sb = t.get(a)
                    if sb is None: sb = "v%d" % a
                    sr(t, a, "(" + sb + ")")
                elif R in BP: sr(t, a, "(%s %s %s)" % (
                    sy(t, b), BP[R], sy(t, c)))
                elif R == 13: sr(t, a, "(-" + sy(t, b) + ")")
                elif R == 14: sr(t, a, "(not " + sy(t, b) + ")")
                elif R == 15: sr(t, a, "#" + sy(t, b))
                elif R == 22:
                    fn = sy(t, a); na = b - 1
                    if na < 0: na = 0
                    ag = [sy(t, a + 1 + j) for j in range(na)]
                    cl_ = "%s(%s)" % (fn, ", ".join(ag))
                    if c <= 2:
                        out.append(pr + cl_); sr(t, a, None)
                    else:
                        out.append(pr + "v%d = %s" % (a, cl_))
                        sr(t, a, "v%d" % a)
                elif R == 23:
                    nr = b - 1
                    if nr <= 0: out.append(pr + "return")
                    else:
                        out.append(pr + "return " +
                                   ", ".join(sy(t, a + j)
                                             for j in range(nr)))
                elif R == 24:
                    out.append(pr + "v%d = {}" % a); sr(t, a, "v%d" % a)
                elif R == 25: sr(t, a, "%s[%s]" % (sy(t, b), sy(t, c)))
                elif R == 26:
                    out.append(pr + "%s[%s] = %s" % (
                        sy(t, a), sy(t, b), sy(t, c)))
                elif R == 27:
                    g = lk(p, b)
                    if isinstance(g, str) and ir.match(g): sr(t, a, g)
                    else: sr(t, a, "_G[%s]" % lt(g))
                elif R == 28:
                    g = lk(p, b); v = sy(t, a)
                    if isinstance(g, str) and ir.match(g):
                        out.append(pr + "%s = %s" % (g, v))
                    else:
                        out.append(pr + "_G[%s] = %s" % (lt(g), v))
                elif R == 29:
                    sc[0] += 1; fn = "f%d" % sc[0]
                    sub = ps[b] if 0 <= b < len(ps) else None
                    pm = (sub.get('pm', 0) or 0) if sub else 0
                    va = (sub.get('va', 0) or 0) if sub else 0
                    prs = ["p%d" % i for i in range(pm)]
                    if va > 0: prs.append("...")
                    if not prs: prs.append("...")
                    out.append(pr + "local function %s(%s)"
                               % (fn, ", ".join(prs)))
                    if sub is not None:
                        st0_ = {i: "p%d" % i for i in range(pm)}
                        out.extend(dec(sub, dd + 1, st0_))
                    out.append(pr + "end")
                    sr(t, a, fn)
                elif R == 30: pass
                elif R == 32:
                    sb = t.get(b)
                    if sb is None: sb = "v%d" % b
                    sr(t, a, sb)
                elif R == 33: pass
                elif R == 35:
                    fn = lk(p, b); ag = lk(p, c)
                    if isinstance(fn, str) and ir.match(fn):
                        out.append(pr + "%s(%s)" % (fn, lt(ag)))
                    elif fn is not None:
                        out.append(pr + "_G[%s](%s)" % (lt(fn), lt(ag)))
                    sr(t, a, None)
                elif R >= 36:
                    us.add(R)
                else:
                    out.append(pr + "-- op %d a=%d b=%d c=%d"
                               % (R, a, b, c))
                i += 1

        em(0, n, d0, st0 if st0 is not None else {})
        return out

    body = dec(ps[1], 0)

    rn = {}; ct = [0]; nb = []
    for line in body:
        def rp(mo):
            o = int(mo.group(1))
            if o not in rn: rn[o] = ct[0]; ct[0] += 1
            return "v%d" % rn[o]
        nb.append(re.sub(r'\bv(\d+)\b', rp, line))

    ol = []
    if ct[0]:
        ol.append("local " + ", ".join("v%d" % i for i in range(ct[0])))
    ol.extend(nb)

    vmap = {
        'v012': 'v0.012', 'v001': 'v0.001', 'v003': 'v0.003',
        'v004': 'v0.004', 'v008': 'v0.008', 'v009': 'v0.009',
        'v007c': 'v0.007', 'v006c': 'v0.006', 'v005': 'v0.005',
    }
    return "\n".join(ol), "ironbrew0 " + vmap.get(ly, ly or 'unknown')


def ppn(d):
    p = [0]
    L = len(d)

    def u8():
        v = d[p[0]] if p[0] < L else 0
        p[0] += 1
        return v

    def u16():
        return (u8() << 8) | u8()

    def u32():
        v = (u8() << 24) | (u8() << 16) | (u8() << 8) | u8()
        if v >= 0x80000000: v -= 0x100000000
        return v

    np = u16()
    ps = [None]
    for _ in range(np):
        nc = u16()
        ki = u8()
        ks = u8()
        od = [u8() for _ in range(nc)]
        ops = []; aa = []; bb = []; cc = []
        k = ki
        for _ in range(nc):
            eo = u8(); ea = u8(); eb = u8(); ec = u8()
            o = xo(eo, k); k = (k * 3 + eo + ks) & 0xFF
            a = xo(ea, k); k = (k * 3 + ea + ks) & 0xFF
            b = xo(eb, k); k = (k * 3 + eb + ks) & 0xFF
            c = xo(ec, k); k = (k * 3 + ec + ks) & 0xFF
            ops.append(o); aa.append(a); bb.append(b); cc.append(c)
        nk = u16()
        cs = [None]
        for _ in range(nk):
            t = u8()
            if t == 167:
                cs.append(-u16())
            elif t == 60:
                cs.append(u32())
            else:
                cs.append(0)
        pm = u16()
        va = u8()
        nn = u16()
        nest = [u16() for _ in range(nn)]
        ps.append({'ops': ops, 'as': aa, 'bs': bb, 'cs': cc, 'ord': od,
                   'consts': cs, 'pm': pm, 'va': va, 'nest': nest, 'nc': nc})
    return ps


def on(t):
    if t.startswith('elseif'): return 0
    if re.match(r'^if\b.*\bthen$', t): return 1
    if re.match(r'^for\b.*\bdo$', t): return 1
    if re.match(r'^while\b.*\bdo$', t): return 1
    if t == 'do': return 1
    if t.startswith('function ') or t.startswith('local function '): return 1
    if re.match(r'^[\w.]+\s*=\s*function\b', t): return 1
    if t == 'repeat': return 1
    return 0


def ce(t):
    if t == 'end': return 1
    if t.startswith('until'): return 1
    return 0


def ra(ln):
    o = []
    i = 0
    n = len(ln)
    while i < n:
        l = ln[i]
        t = l.strip()
        if re.match(r'^v\d+ = -?\d+$', t):
            j = i
            while j < n and re.match(r'^\s*v\d+ = -?\d+\s*$', ln[j]):
                j += 1
            if j < n:
                tj = ln[j].strip()
                if tj.startswith('if ') and tj.endswith(' then') and not tj.startswith('elseif'):
                    k = j + 1; d = 1; h = False
                    while k < n and d > 0:
                        tk = ln[k].strip()
                        if 'IronBrew0 VM' in ln[k]: h = True
                        d += on(tk) - ce(tk)
                        k += 1
                    if h:
                        i = k
                        continue
            o.append(l); i += 1; continue
        if t.startswith('if ') and t.endswith(' then') and not t.startswith('elseif'):
            k = i + 1; d = 1; h = False
            while k < n and d > 0:
                tk = ln[k].strip()
                if 'IronBrew0 VM' in ln[k]: h = True
                d += on(tk) - ce(tk)
                k += 1
            if h:
                i = k
                continue
        o.append(l); i += 1
    return o


def rd(ln):
    def a1(l):
        return re.match(r'^\s*v\d+\s*=\s*(-?\d+|nil|true|false)\s*$', l) is not None
    def a2(l):
        return re.match(r'^\s*local\s+v\d+(?:\s*,\s*v\d+)*\s*$', l) is not None
    u = set()
    for l in ln:
        if a1(l) or a2(l): continue
        for m in re.finditer(r'\bv\d+\b', ss(l)):
            u.add(m.group(0))
    o = []
    for l in ln:
        if a1(l):
            m = re.match(r'^\s*(v\d+)\s*=', l)
            if m and m.group(1) not in u:
                continue
        o.append(l)
    return o


def rt(ln):
    o = []
    n = len(ln)
    i = 0
    while i < n:
        l = ln[i]
        t = l.strip()
        if t == 'return' or re.match(r'^return v\d+(, v\d+)*$', t):
            ci = idn(l)
            j = i + 1
            while j < n and not ln[j].strip():
                j += 1
            if j < n:
                tj = ln[j].strip()
                if idn(ln[j]) >= ci and tj not in ('end', 'else', 'until') \
                   and not tj.startswith('elseif'):
                    i += 1
                    continue
        o.append(l)
        i += 1
    return o


def rs(ln):
    o = []
    i = 0
    n = len(ln)
    while i < n:
        l = ln[i]
        t = l.strip()
        if re.match(r'^(local function \w+|\w+ = function\b)', t):
            ci = idn(l)
            j = i + 1
            bd = []
            while j < n:
                lj = ln[j]
                if not lj.strip():
                    bd.append(lj); j += 1; continue
                if idn(lj) <= ci:
                    break
                bd.append(lj)
                j += 1
            if j < n and ln[j].strip() == 'end':
                tv = True
                for b in bd:
                    bs = b.strip()
                    if not bs: continue
                    if bs.startswith('-- cyclic proto'): continue
                    if bs == 'return': continue
                    tv = False
                    break
                if tv:
                    i = j + 1
                    continue
        o.append(l)
        i += 1
    return o


def ry(ln):
    return [l for l in ln if not re.match(r'^\s*type\(', l)]


def rv(ln):
    if not ln: return ln
    m = re.match(r'^local (v\d+(?:\s*,\s*v\d+)*)$', ln[0].strip())
    if not m: return ln
    vn = [x.strip() for x in m.group(1).split(',')]
    rest = ln[1:]
    u = set()
    for l in rest:
        for mm in re.finditer(r'\bv\d+\b', ss(l)):
            u.add(mm.group(0))
    kp = [v for v in vn if v in u]
    if not kp:
        return rest
    if len(kp) == len(vn):
        return ln
    return ["local " + ", ".join(kp)] + rest


def cl(ln):
    for _ in range(4):
        a = len(ln)
        ln = ra(ln)
        ln = rt(ln)
        ln = rs(ln)
        ln = ry(ln)
        ln = rd(ln)
        ln = rv(ln)
        if len(ln) == a: break
    return ln


CFG = {
    'v1.3': {
        'st': 'cI68', 'sk1': 'pY45', 'sk2': 'NH69',
        'bt': 'S1q',  'bk1': 'F21',  'bk2': 'i50',
        'ot': 'tW77', 'ok1': 'JQ86',
        'lt': 'LO49', 'lk1': 'LO49m',
        'sd1': 'G75', 'sd2': 'DV16', 'sd3': 'i50',
        'zm': {50: 22, 54: 23, 55: 1, 57: 35, 64: 29},
    },
    'v1.4': {
        'st': 'Ef59', 'sk1': 'Up',  'sk2': 'CO',
        'bt': 'fNb',  'bk1': 'p32', 'bk2': 'o22',
        'ot': 'Pi',   'ok1': 'sW56',
        'lt': 'HY12', 'lk1': 'HY12m',
        'sd1': 'A40', 'sd2': 'xL8', 'sd3': 'o22',
        'zm': {85: 19, 86: 7, 87: 30, 93: 23, 100: 14, 101: 22,
               104: 2, 107: 27, 111: 35, 112: 9, 115: 16, 118: 6,
               121: 20, 127: 29, 132: 8},
    },
}


def nd(s, ver):
    C = CFG.get(ver)
    if C is None:
        return None
    z2 = C['zm']

    A = ar(br(s, C['st']))
    B = ar(br(s, C['bt']))
    Pi = ar(br(s, C['ot']))
    HY = ar(br(s, C['lt']))
    if not (A and B and Pi and HY):
        return None

    Up = gv(s, C['sk1']); CO = gv(s, C['sk2'])
    p3 = gv(s, C['bk1']); o2 = gv(s, C['bk2'])
    s5 = gv(s, C['ok1']); hm = gv(s, C['lk1'])
    a4 = gv(s, C['sd1']); x8 = gv(s, C['sd2'])
    if None in (Up, CO, p3, o2, s5, hm, a4, x8):
        return None

    k = Up
    dk = []
    for x in A:
        y = xo(x, k)
        dk.append(y)
        k = (k * 3 + x + CO) & 0xFF

    pos = [0]

    def r8():
        v = dk[pos[0]] if pos[0] < len(dk) else 0
        pos[0] += 1
        return v

    def r16():
        return (r8() << 8) | r8()

    ns = r16()
    GI = [None]
    for _ in range(ns):
        ln = r16()
        GI.append([r8() for _ in range(ln)])

    k = p3
    db = []
    for x in B:
        y = xo(x, k)
        db.append(y)
        k = (k * 3 + x + o2) & 0xFF

    ps = ppn(db)

    tu = [0] * 256
    Lp = len(Pi)
    for z in range(256):
        a = Pi[z - 1] if 1 <= z <= Lp else 0
        tu[z] = (a ^ s5) & 0xFF

    def cr(i):
        kk = (a4 + (i - 1) * x8) & 0xFF
        a = GI[i] if 1 <= i < len(GI) else []
        o = []
        for v in a:
            d = xo(v, kk)
            o.append(chr(d))
            kk = (kk * 3 + v + o2) & 0xFF
        return ''.join(o)

    def lk(p, i):
        cs = p['consts']
        if i < 0 or i >= len(cs): return None
        v = cs[i]
        if v is None: return None
        if isinstance(v, int) and v < 0: return cr(-v)
        return v

    def lt(v):
        if v is None: return "nil"
        if isinstance(v, bool): return "true" if v else "false"
        if isinstance(v, str):
            e = v.replace('\\', '\\\\').replace("'", "\\'")
            e = e.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
            return "'" + e + "'"
        return str(v)

    ir = re.compile(r'^[A-Za-z_]\w*$')
    sc = [0]
    us = set()
    cu = set()

    def dc(p, d0, st0=None, pi=None):
        if pi is not None:
            if pi in cu:
                return ["-- recursive proto %d" % pi]
            cu.add(pi)

        n = p['nc']
        od_ = p.get('ord') or []
        ops = []
        for i in range(n):
            akph = i + 1
            if i < len(od_) and od_[i] >= 1:
                akph = od_[i]
            idx = akph - 1
            if idx < 0 or idx >= n:
                idx = i
            raw = p['ops'][idx]
            it = tu[raw] if 0 <= raw < 256 else 0
            if 1 <= it <= len(HY):
                zb = HY[it - 1] ^ (hm ^ (it & 0xFF))
                op = z2.get(zb, 0)
            else:
                op = 0
            ops.append((op, p['as'][idx], p['bs'][idx], p['cs'][idx]))

        o = []

        def sy(t, r):
            if r in t and t[r] is not None: return t[r]
            return "v%d" % r

        def sr(t, r, v):
            w = "v%d" % r
            for kk in [k for k, vv in t.items() if vv == w and k != r]:
                t[kk] = None
            t[r] = v

        def em(i0, j0, dd, t):
            pr = "  " * dd; i = i0
            while i < j0:
                R, a, b, c = ops[i]

                if R == 19:
                    i = i + sg(a); continue

                if R == 20 or R == 21:
                    tg = i + sg(a)
                    if tg > j0: tg = j0
                    el = None
                    if tg - 1 > i and tg - 1 < j0:
                        p2, q2, _, _ = ops[tg - 1]
                        if p2 == 19:
                            el = tg - 1 + sg(q2)
                            if el > j0: el = j0
                    cd = sy(t, b)
                    if el is not None:
                        if R == 21:
                            o.append(pr + "if " + cd + " then")
                            em(i + 1, tg - 1, dd + 1, dict(t))
                            o.append(pr + "else")
                            em(tg, el, dd + 1, dict(t))
                            o.append(pr + "end")
                        else:
                            o.append(pr + "if not " + cd + " then")
                            em(i + 1, tg - 1, dd + 1, dict(t))
                            o.append(pr + "else")
                            em(tg, el, dd + 1, dict(t))
                            o.append(pr + "end")
                        i = el
                    else:
                        if R == 21:
                            o.append(pr + "if " + cd + " then")
                        else:
                            o.append(pr + "if not " + cd + " then")
                        em(i + 1, tg, dd + 1, dict(t))
                        o.append(pr + "end")
                        i = tg
                    t.clear(); continue

                if R == 1:
                    sb = t.get(b)
                    if sb is None: sb = "v%d" % b
                    sr(t, a, sb)
                elif R == 2 or R == 31:
                    kv = lk(p, b)
                    if isinstance(kv, str):
                        sr(t, a, lt(kv))
                    else:
                        o.append(pr + "v%d = %s" % (a, lt(kv)))
                        sr(t, a, "v%d" % a)
                elif R == 3:
                    sr(t, a, "nil")
                elif R == 4:
                    sr(t, a, "true" if b else "false")
                elif R == 5:
                    sb = t.get(a)
                    if sb is None: sb = "v%d" % a
                    sr(t, a, "(" + sb + ")")
                elif R in BP:
                    sr(t, a, "(%s %s %s)" % (sy(t, b), BP[R], sy(t, c)))
                elif R == 13:
                    sr(t, a, "(-" + sy(t, b) + ")")
                elif R == 14:
                    sr(t, a, "(not " + sy(t, b) + ")")
                elif R == 15:
                    sr(t, a, "#" + sy(t, b))
                elif R == 22:
                    fn = sy(t, a); na = b - 1
                    if na < 0: na = 0
                    ag = [sy(t, a + 1 + j) for j in range(na)]
                    ac = "%s(%s)" % (fn, ", ".join(ag))
                    if c <= 2:
                        o.append(pr + ac); sr(t, a, None)
                    else:
                        o.append(pr + "v%d = %s" % (a, ac))
                        sr(t, a, "v%d" % a)
                elif R == 23:
                    nr = b - 1
                    if nr <= 0:
                        o.append(pr + "return")
                    else:
                        o.append(pr + "return " +
                                   ", ".join(sy(t, a + j) for j in range(nr)))
                elif R == 24:
                    o.append(pr + "v%d = {}" % a); sr(t, a, "v%d" % a)
                elif R == 25:
                    sr(t, a, "%s[%s]" % (sy(t, b), sy(t, c)))
                elif R == 26:
                    o.append(pr + "%s[%s] = %s"
                             % (sy(t, a), sy(t, b), sy(t, c)))
                elif R == 27:
                    g = lk(p, b)
                    if isinstance(g, str) and ir.match(g):
                        sr(t, a, g)
                    else:
                        sr(t, a, "_G[%s]" % lt(g))
                elif R == 28:
                    g = lk(p, b); v = sy(t, a)
                    if isinstance(g, str) and ir.match(g):
                        o.append(pr + "%s = %s" % (g, v))
                    else:
                        o.append(pr + "_G[%s] = %s" % (lt(g), v))
                elif R == 29:
                    sc[0] += 1; fn = "f%d" % sc[0]
                    sub = ps[b] if 0 <= b < len(ps) else None
                    pm = (sub.get('pm', 0) or 0) if sub else 0
                    va = (sub.get('va', 0) or 0) if sub else 0
                    prs = ["p%d" % i for i in range(pm)]
                    if va > 0: prs.append("...")
                    if not prs: prs.append("...")
                    o.append(pr + "local function %s(%s)"
                             % (fn, ", ".join(prs)))
                    if sub is not None and b not in cu:
                        s0 = {i: "p%d" % i for i in range(pm)}
                        o.extend(dc(sub, dd + 1, s0, b))
                    elif sub is not None:
                        o.append(pr + "  -- cyclic proto %d" % b)
                    o.append(pr + "end")
                    sr(t, a, fn)
                elif R == 30:
                    pass
                elif R == 32:
                    sb = t.get(b)
                    if sb is None: sb = "v%d" % b
                    sr(t, a, sb)
                elif R == 33:
                    pass
                elif R == 35:
                    fn = lk(p, b); ag = lk(p, c)
                    if isinstance(fn, str) and ir.match(fn):
                        o.append(pr + "%s(%s)" % (fn, lt(ag)))
                    elif fn is not None:
                        o.append(pr + "_G[%s](%s)" % (lt(fn), lt(ag)))
                    sr(t, a, None)
                elif R >= 36:
                    us.add(R)
                else:
                    o.append(pr + "-- op %d a=%d b=%d c=%d" % (R, a, b, c))
                i += 1

        em(0, n, d0, st0 if st0 is not None else {})
        if pi is not None:
            cu.discard(pi)
        return o

    body = dc(ps[1], 0, None, 1)

    rn = {}
    ct = [0]

    def rp(nm):
        o = int(nm[1:])
        if o not in rn:
            rn[o] = ct[0]
            ct[0] += 1
        return "v%d" % rn[o]

    nb = [sv(l, rp) for l in body]

    ol = []
    if ct[0]:
        ol.append("local " + ", ".join("v%d" % i for i in range(ct[0])))
    ol.extend(nb)
    ol = cl(ol)

    return "\n".join(ol)


def dobf(src):
    if isinstance(src, str) and os.path.isfile(src):
        with open(src, encoding='utf-8') as f:
            src = f.read()

    m = re.search(r'ironbrew0:tm:(v[\d.]+)', src)
    if m and m.group(1) in CFG:
        out = nd(src, m.group(1))
        if out is not None:
            return out, "ironbrew0 " + m.group(1)

    out, ver = od(src)
    if out is not None:
        return out, ver

    return None, None


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("usage: python %s <file.lua|file.luau|file.txt>" % sys.argv[0])
        sys.exit(1)
    src, ver = dobf(sys.argv[1])
    if src is None:
        print("could not deobfuscate")
    else:
        print("version: %s" % ver)
        print(src)