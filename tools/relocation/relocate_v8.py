#!/usr/bin/env python3
"""v8：收尾三件套。
A) Encoder 精筛：两个 BL（write + protobuf 区）、strb wzr,[x3]、mov w0,#1、短函数
B) req2buf 区域 DP 对齐：映射 Req2Buf/Enter/blrX8/Exit
C) SendAsync 新旧 BL 目标序列对齐：dtor 目标投票 + ctor 复核
"""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)


def read_text(path, fat, size):
    with open(path, 'rb') as f:
        f.seek(fat)
        return f.read(size)


OLD = read_text('/tmp/wxrelocate/wechat_4_1_11.dylib', 0xa344000, 0x8f2c000)
NEW = read_text('/Applications/wechat.app/Contents/Resources/wechat.dylib', 0xaab0000, 0x9694000)


def disasm(text, off, size):
    return list(md.disasm(text[off:off + size], off))


def parse_imm(token):
    token = token.strip().lstrip('#')
    return int(token, 16) if token.lower().startswith('0x') else int(token)


def bls(insns):
    out = []
    for insn in insns:
        if insn.mnemonic == 'bl':
            try:
                out.append((insn.address, parse_imm(insn.op_str)))
            except ValueError:
                pass
    return out


encoder_candidates = [0x2f3cddc, 0x34d65cc, 0x3a78d80, 0x4276230, 0x42f5a7c, 0x42f8748,
                      0x42fb5c4, 0x42fe290, 0x4300bb0, 0x43034d0, 0x43a6aa0, 0x43a9da4,
                      0x43ad070, 0x43b39f8, 0x4463144, 0x4835674]

print('== A) Encoder 精筛 ==')
for cand in encoder_candidates:
    seg = disasm(NEW, cand, 0xc0)
    texts = [f'{x.mnemonic} {x.op_str}' for x in seg[:24]]
    call_list = bls(seg)
    write_calls = [c for _, c in call_list if c == 0x43084c0]
    proto_calls = [c for _, c in call_list if 0x5700000 <= c <= 0x5720000]
    has_strb_x3 = any(t.startswith('strb wzr, [x3]') for t in texts)
    has_mov1 = any(t.startswith('mov w0, #1') or t == 'mov w0, #1' for t in texts)
    ret_at = next((x.address - cand for x in seg if x.mnemonic == 'ret'), None)
    ok = len(write_calls) >= 1 and len(proto_calls) >= 1 and has_strb_x3
    mark = '<<<' if ok else ''
    print(f'{hex(cand)}: write×{len(write_calls)} proto×{len(proto_calls)} strb_x3={has_strb_x3} mov1={has_mov1} ret@{hex(ret_at) if ret_at else "?"} {mark}')
    if ok:
        for t in texts[:20]:
            print(f'    {t}')

print('\n== B) req2buf 区域对齐 ==')
OLD_REGION_START, OLD_REGION_SIZE = 0x3e58c00, 0x1244
NEW_REGION_START, NEW_REGION_SIZE = 0x4305e00, 0x1200
old_ins = disasm(OLD, OLD_REGION_START, OLD_REGION_SIZE)
new_ins = disasm(NEW, NEW_REGION_START, NEW_REGION_SIZE)


def mask(insn):
    word = struct.unpack_from('<I', insn.bytes, 0)[0]
    m = 0xFFFFFFFF
    mne = insn.mnemonic
    if mne == 'adrp':
        m = 0x8000001F & ~0x000000E0
    elif mne in ('b', 'bl'):
        m = 0xFC000000
    elif mne == 'b.cond' or mne.startswith('cbz') or mne.startswith('cbnz'):
        m = 0xFF00001F & ~0x00FFFFE0
    elif mne.startswith('tbz') or mne.startswith('tbnz'):
        m = 0xFF80001F & ~0x007FFFE0
    return word, m


def eq(i, j):
    wi, mi = mask(old_ins[i])
    wj, _ = mask(new_ins[j])
    return (wi & mi) == (wj & mi)


n, m = len(old_ins), len(new_ins)
GAP, MATCH, MISS = -1, 2, -2
dp = [[0] * (m + 1) for _ in range(n + 1)]
for i in range(1, n + 1):
    dp[i][0] = dp[i - 1][0] + GAP
for j in range(1, m + 1):
    dp[0][j] = dp[0][j - 1] + GAP
for i in range(1, n + 1):
    for j in range(1, m + 1):
        best = dp[i - 1][j - 1] + (MATCH if eq(i - 1, j - 1) else MISS)
        if dp[i - 1][j] + GAP > best:
            best = dp[i - 1][j] + GAP
        if dp[i][j - 1] + GAP > best:
            best = dp[i][j - 1] + GAP
        dp[i][j] = best
i, j = n, m
mapping = {}
while i > 0 and j > 0:
    score = dp[i][j]
    if score == dp[i - 1][j - 1] + (MATCH if eq(i - 1, j - 1) else MISS):
        mapping[i - 1] = j - 1
        i, j = i - 1, j - 1
    elif score == dp[i - 1][j] + GAP:
        i -= 1
    else:
        j -= 1
matched = sum(1 for a, b in mapping.items() if eq(a, b))
print(f'区域对齐: {len(mapping)} 条, 结构匹配 {matched}')

for label, old_off in [('realTextReq2Buf', 0x3e58e44), ('req2bufEnter', 0x3e58e8c),
                       ('blrX8', 0x3e58f0c), ('req2bufExit', 0x3e59de0)]:
    rel = (old_off - OLD_REGION_START) // 4
    if rel in mapping:
        new_addr = NEW_REGION_START + mapping[rel] * 4
        print(f'{label:16} {hex(old_off)} -> {hex(new_addr)}  (局部指令: {old_ins[rel].mnemonic} {old_ins[rel].op_str} | {new_ins[mapping[rel]].mnemonic} {new_ins[mapping[rel]].op_str})')
    else:
        print(f'{label:16} {hex(old_off)} 未对齐')

print('\n== C) SendAsync BL 序列对齐 ==')
OLD_SA, NEW_SA = 0x2a34cbc, 0x21f3380
old_bls = bls(disasm(OLD, OLD_SA, 0x1100))
new_bls = bls(disasm(NEW, NEW_SA, 0x1100))
print(f'旧 BL 数 {len(old_bls)}, 新 BL 数 {len(new_bls)}')
KNOWN = {0x3e7fa8c: 0x43084c0, 0x3e7fb30: 0x4308564, 0x3e7faf0: 0x4308524,
         0x5256c98: 0x5705bdc, 0x3ebd8a8: 0x430a354}
# 已锚定的目标对
anchor_pairs = [(ot, KNOWN[ot]) for _, ot in old_bls if ot in KNOWN]
print('锚点对:', [(hex(a), hex(b)) for a, b in anchor_pairs])
# 序列 DP（以 BL 目标序列为元素：已知目标相等才 match，未知目标位置对齐得分为弱 match）
n2, m2 = len(old_bls), len(new_bls)
dp2 = [[0] * (m2 + 1) for _ in range(n2 + 1)]
for i in range(1, n2 + 1):
    dp2[i][0] = dp2[i - 1][0] + GAP
for j in range(1, m2 + 1):
    dp2[0][j] = dp2[0][j - 1] + GAP


def seq_eq(i, j):
    ot = old_bls[i][1]
    nt = new_bls[j][1]
    if ot in KNOWN:
        return KNOWN[ot] == nt
    return None  # 未知


for i in range(1, n2 + 1):
    for j in range(1, m2 + 1):
        e = seq_eq(i - 1, j - 1)
        score = MATCH if e is True else (0 if e is None else MISS)
        best = dp2[i - 1][j - 1] + score
        if dp2[i - 1][j] + GAP > best:
            best = dp2[i - 1][j] + GAP
        if dp2[i][j - 1] + GAP > best:
            best = dp2[i][j - 1] + GAP
        dp2[i][j] = best
i, j = n2, m2
seq_map = {}
while i > 0 and j > 0:
    e = seq_eq(i - 1, j - 1)
    score = MATCH if e is True else (0 if e is None else MISS)
    if dp2[i][j] == dp2[i - 1][j - 1] + score:
        seq_map[i - 1] = j - 1
        i, j = i - 1, j - 1
    elif dp2[i - 1][j] + GAP > dp2[i][j - 1] + GAP:
        i -= 1
    else:
        j -= 1

# 对旧 dtor/ctor 调用点投票
for label, old_target in [('PayloadDtor', 0x3ebf130), ('RequestCtor', 0x2a35ac8)]:
    votes = {}
    for idx, (site, target) in enumerate(old_bls):
        if target != old_target or idx not in seq_map:
            continue
        nt = new_bls[seq_map[idx]][1]
        votes[nt] = votes.get(nt, 0) + 1
    print(f'{label} 目标投票: ' + (', '.join(f'{hex(t)}×{c}' for t, c in sorted(votes.items(), key=lambda kv: -kv[1])) or '无'))
