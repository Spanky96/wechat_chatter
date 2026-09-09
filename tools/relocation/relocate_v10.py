#!/usr/bin/env python3
"""v10：终局。
1) 读新 ctor/Response 写入的 vtable，在 vtable 内容中反查 encoder/dtor 候选
2) 在预测 Enter(≈0x4306DA8) 附近做寄存器无关操作码序列匹配
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


def vtables_written(insns):
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
            if pb[1] != pa[0] or pc[0] != pb[0] or pc[1] not in ('[x0]', '[x19]'):
                continue
            out.append(parse_imm(pa[2]) + parse_imm(pb[2]))
        except (ValueError, IndexError):
            continue
    return out


def read_vtable_entries(text, vtaddr, count=16):
    entries = []
    for k in range(count):
        off = vtaddr + k * 8
        if off + 8 > len(text):
            break
        entries.append(struct.unpack_from('<Q', text, off)[0])
    return entries


print('== 1) vtable 反查 ==')
encoder_candidates = [0x2f3cddc, 0x34d65cc, 0x3a78d80, 0x4276230, 0x42f5a7c, 0x42f8748,
                      0x42fb5c4, 0x42fe290, 0x4300bb0, 0x43034d0, 0x43a6aa0, 0x43a9da4,
                      0x43ad070, 0x43b39f8, 0x4463144, 0x4835674]
dtor_candidates = [0x43098f0, 0x430a6a8, 0x430afe0, 0x430b010, 0x430bbdc, 0x430bc54,
                   0x430c60c, 0x430d2e0, 0x430d37c]
all_candidates = set(encoder_candidates + dtor_candidates)

for label, func_off, text in [('新PayloadCtor', 0x430a354, NEW), ('新RequestCtor', 0x21f40f0, NEW),
                              ('旧PayloadCtor', 0x3ebd8a8, OLD), ('旧RequestCtor', 0x2a35ac8, OLD)]:
    vts = vtables_written(disasm(text, func_off, 0x80))
    print(f'{label} 写入 vtable: {[hex(v) for v in vts]}')
    src = OLD if text is OLD else NEW
    for vt in vts:
        entries = read_vtable_entries(src, vt)
        hits = [hex(e) for e in entries if e in all_candidates]
        if hits:
            print(f'   vtable {hex(vt)} 内含候选函数: {hits}')
        else:
            print(f'   vtable {hex(vt)} 条目: {[hex(e) for e in entries[:8]]}')

print('\n== 2) Enter/Req2Buf 寄存器无关匹配 ==')
# 旧 Enter 处操作码序列（红黑树查找舞步）
old_window = disasm(OLD, 0x3e58e8c, 0x60)
old_shape = [i.mnemonic for i in old_window]
print('旧 Enter 操作码序列:', ' '.join(old_shape[:16]))

search_lo, search_hi = 0x4306400, 0x4307bc0
new_ins = disasm(NEW, search_lo, search_hi - search_lo)
hits = []
for j in range(len(new_ins) - len(old_shape)):
    window = new_ins[j:j + len(old_shape)]
    if [w.mnemonic for w in window] == old_shape:
        hits.append(window[0].address)
print(f'操作码序列命中: {[hex(h) for h in hits]}')
