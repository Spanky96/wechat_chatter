#!/usr/bin/env python3
"""v9：收官。
1) dtor：新旧 PayloadCtor vtable 对照 → 9 候选中选唯一
2) Encoder：列出全部通过者及其 protobuf 被调地址
3) req2buf：用 BL→(length 兄弟 0x4308570) 的调用序列定位尾部，回推 Enter/Req2Buf
"""
import struct
from array import array as A
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


def vtables_written(insns):
    """adrp+add → str Xn,[x0] 或 str Xn,[x19] 的 vtable 值。"""
    out = []
    for i in range(len(insns) - 2):
        a, b, c = insns[i], insns[i + 1], insns[i + 2]
        if a.mnemonic != 'adrp' or b.mnemonic != 'add' or c.mnemonic != 'str':
            continue
        try:
            pa = [p.strip() for p in a.op_str.split(',')]
            pb = [p.strip() for p in b.op_str.split(',')]
            pc = [p.strip() for p in c.op_str.split(',')]
            if len(pa) < 3 or len(pb) < 3 or len(pc) < 2:
                continue
            if pb[1] != pa[0] or pc[0] != pb[0]:
                continue
            if pc[1] not in ('[x0]', '[x19]'):
                continue
            out.append((a.address, parse_imm(pa[2]) + parse_imm(pb[2])))
        except (ValueError, IndexError):
            continue
    return out


print('== 1) PayloadCtor/ctor vtable 对照 ==')
old_ctor_vt = vtables_written(disasm(OLD, 0x3ebd8a8, 0x80))
new_ctor_vt = vtables_written(disasm(NEW, 0x430a354, 0x80))
print('旧 ctor vtable:', [(hex(a), hex(v)) for a, v in old_ctor_vt])
print('新 ctor vtable:', [(hex(a), hex(v)) for a, v in new_ctor_vt])
if new_ctor_vt:
    target = new_ctor_vt[0][1]
    print(f'在 dtor 候选中找写 vtable {hex(target)} 的:')
    for cand in [0x43098f0, 0x430a6a8, 0x430afe0, 0x430b010, 0x430bbdc, 0x430bc54, 0x430c60c, 0x430d2e0, 0x430d37c]:
        vt = vtables_written(disasm(NEW, cand, 0x40))
        mark = ' <== 匹配' if vt and vt[0][1] == target else ''
        print(f'  {hex(cand)}: {[hex(v) for _, v in vt]}{mark}')

print('\n== 2) Encoder 通过者完整列表 ==')
encoder_candidates = [0x2f3cddc, 0x34d65cc, 0x3a78d80, 0x4276230, 0x42f5a7c, 0x42f8748,
                      0x42fb5c4, 0x42fe290, 0x4300bb0, 0x43034d0, 0x43a6aa0, 0x43a9da4,
                      0x43ad070, 0x43b39f8, 0x4463144, 0x4835674]
for cand in encoder_candidates:
    seg = disasm(NEW, cand, 0xc0)
    texts = [f'{x.mnemonic} {x.op_str}' for x in seg[:24]]
    call_list = [(x.address, parse_imm(x.op_str)) for x in seg if x.mnemonic == 'bl']
    write_calls = [c for _, c in call_list if c == 0x43084c0]
    proto_calls = [c for _, c in call_list if 0x5700000 <= c <= 0x5720000]
    has_strb_x3 = any(t.startswith('strb wzr, [x3]') for t in texts)
    if write_calls and proto_calls and has_strb_x3:
        addoff = next((t for t in texts if t.startswith('add x0, x0, #')), '?')
        print(f'  {hex(cand)}: proto调用 {[hex(c) for c in proto_calls]}, {addoff}')

print('\n== 3) req2buf 尾部定位 ==')
# AutoBuffer 家族布局: write 0x43084c0, data 0x4308524, length 0x4308564
# 旧兄弟: 0x3e7fb3c = length+0xC → 新 0x4308570; 0x3e7f950 = write-0x13C → 新 0x4308384
FAMILY = {0x4308384, 0x43084c0, 0x4308524, 0x4308564, 0x4308570}
wa = A('I')
with open('/Applications/wechat.app/Contents/Resources/wechat.dylib', 'rb') as f:
    f.seek(0xaab0000)
    raw = f.read(0x9694000)
wa.frombytes(raw)
import sys
if sys.byteorder != 'little':
    wa.byteswap()
family_sites = {t: [] for t in FAMILY}
for idx in range(len(wa)):
    w = wa[idx]
    if (w & 0xFC000000) != 0x94000000:
        continue
    imm = w & 0x03FFFFFF
    if imm & 0x02000000:
        imm -= 0x04000000
    t = idx * 4 + imm * 4
    if t in family_sites:
        family_sites[t].append(idx * 4)

# 旧尾部序列 (0x3e59ca8..0x3e59da0): [8570,8564,8564,8564,8570,8564,8384,8384]
# 在新区找 8570 调用点，其后 0x120 内应有 4 个 8564
length_sites = set(family_sites[0x4308564])
tail_candidates = []
for site8570 in family_sites[0x4308570]:
    near_lengths = [s for s in family_sites[0x4308564] if site8570 < s < site8570 + 0x140]
    if len(near_lengths) >= 3:
        tail_candidates.append((site8570, near_lengths))
for s, nl in tail_candidates:
    print(f'  尾部候选: 8570@{hex(s)} 后续 8564 调用 {[hex(x) for x in nl]}')
