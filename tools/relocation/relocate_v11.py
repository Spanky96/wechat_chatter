#!/usr/bin/env python3
"""v11：终极判定。
1) 解析完整段表（__DATA_CONST/__DATA）
2) 宽松 vtable 提取（adrp+add 允许交错，str 到 [x0]/[x19] 限 6 条内）
3) 在数据段反查候选地址的 QWORD 引用 → 判定哪个 vtable 引用哪个候选
4) 全局操作码序列搜索 Enter
"""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)


def parse_segments(path, fat_off):
    with open(path, 'rb') as f:
        f.seek(fat_off)
        head = f.read(0x10000)
    ncmds = struct.unpack_from('<I', head, 16)[0]
    off = 32
    segs = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', head, off)
        if cmd == 0x19:
            name = head[off + 8:off + 24].rstrip(b'\0').decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', head, off + 24)
            if filesize:
                segs.append((name, vmaddr, vmsize, fileoff, filesize))
        off += cmdsize
    return segs


NEW_PATH = '/Applications/wechat.app/Contents/Resources/wechat.dylib'
OLD_PATH = '/tmp/wxrelocate/wechat_4_1_11.dylib'
new_segs = parse_segments(NEW_PATH, 0xaab0000)
print('新段表:', [(n, hex(v), hex(vs), hex(fo), hex(fs)) for n, v, vs, fo, fs in new_segs if fs > 0x100000])


def read_region(path, fat_off, fileoff, size):
    with open(path, 'rb') as f:
        f.seek(fat_off + fileoff)
        return f.read(size)


with open(NEW_PATH, 'rb') as f:
    f.seek(0xaab0000)
    NEW_TEXT = f.read(next(s for s in new_segs if s[0] == '__TEXT')[4])

with open(OLD_PATH, 'rb') as f:
    f.seek(0xa344000)
    OLD_TEXT = f.read(0x8f2c000)


def disasm(text, off, size):
    return list(md.disasm(text[off:off + size], off))


def parse_imm(token):
    token = token.strip().lstrip('#')
    return int(token, 16) if token.lower().startswith('0x') else int(token)


def loose_vtables(insns, maxdist=8):
    """adrp+add 配对（允许交错），随后 maxdist 内 str 到 [x0]/[x19]。"""
    adrp_map = {}
    for i, insn in enumerate(insns):
        if insn.mnemonic != 'adrp':
            continue
        parts = [p.strip() for p in insn.op_str.split(',')]
        if len(parts) == 3:
            try:
                adrp_map.setdefault(parts[0], []).append((i, parse_imm(parts[2])))
            except ValueError:
                pass
    out = []
    for reg, pages in adrp_map.items():
        for i0, page in pages:
            for j in range(i0 + 1, min(i0 + maxdist, len(insns))):
                b = insns[j]
                if b.mnemonic != 'add':
                    continue
                parts = [p.strip() for p in b.op_str.split(',')]
                if len(parts) == 3 and parts[1] == reg and parts[2].startswith('#'):
                    try:
                        full = page + parse_imm(parts[2])
                    except ValueError:
                        continue
                    for k in range(j + 1, min(j + maxdist, len(insns))):
                        c = insns[k]
                        if c.mnemonic == 'str' and c.op_str.endswith((', ' + reg)):
                            out.append(full)
                            break
                    break
    return out


print('\n== 宽松 vtable ==')
for label, off, text in [('新RequestCtor', 0x21f40f0, NEW_TEXT), ('新PayloadCtor', 0x430a354, NEW_TEXT),
                         ('旧RequestCtor', 0x2a35ac8, OLD_TEXT), ('旧PayloadCtor', 0x3ebd8a8, OLD_TEXT)]:
    print(f'{label}: {[hex(v) for v in loose_vtables(disasm(text, off, 0x100))]}')

encoder_candidates = [0x2f3cddc, 0x34d65cc, 0x3a78d80, 0x4276230, 0x42f5a7c, 0x42f8748,
                      0x42fb5c4, 0x42fe290, 0x4300bb0, 0x43034d0, 0x43a6aa0, 0x43a9da4,
                      0x43ad070, 0x43b39f8, 0x4463144, 0x4835674]
dtor_candidates = [0x43098f0, 0x430a6a8, 0x430afe0, 0x430b010, 0x430bbdc, 0x430bc54,
                   0x430c60c, 0x430d2e0, 0x430d37c]

print('\n== 数据段 QWORD 反查候选 ==')
for name, vmaddr, vmsize, fileoff, filesize in new_segs:
    if not (name.startswith('__DATA')):
        continue
    data = read_region(NEW_PATH, 0xaab0000, fileoff, min(filesize, 0x4000000))
    for cand in encoder_candidates + dtor_candidates:
        needle = struct.pack('<Q', cand)
        pos = 0
        refs = []
        while len(refs) < 3:
            idx = data.find(needle, pos)
            if idx < 0:
                break
            refs.append(vmaddr + idx)
            pos = idx + 1
        if refs:
            kind = 'ENC' if cand in encoder_candidates else 'DTOR'
            print(f'  [{kind}] {hex(cand)} 被 {name}@{[hex(r) for r in refs]} 引用')

print('\n== 全局 Enter 操作码搜索 ==')
old_window = disasm(OLD_TEXT, 0x3e58e8c, 0x60)
old_shape = [i.mnemonic for i in old_window][:14]
print('序列:', ' '.join(old_shape))
# 全扫太慢，按 4 字节步进比对 mnemonic 流：先粗定位含 cbnz 回跳 + cset + csel 密集区
# 直接在 0x4305000..0x4307c00 之外扩大到 0x42e0000..0x4310000
lo, hi = 0x42e0000, 0x4310000
insns = disasm(NEW_TEXT, lo, hi - lo)
shape = [w.mnemonic for w in insns]
target = old_shape
n = len(target)
hits = []
for j in range(len(shape) - n):
    if shape[j:j + n] == target:
        hits.append(lo + insns[j].address if insns[j].address else None)
print(f'命中: {[hex(h) for h in hits if h]}')
