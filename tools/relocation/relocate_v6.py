#!/usr/bin/env python3
"""v6：
1) PayloadDtor：从新旧 PayloadCtor 提取各自写入的 vtable，扫新二进制找同样写 vtable 的函数 → dtor
2) 侦察旧 Encoder 形状
3) req2buf：定位旧区域里对 autoBufferWriteFunc(0x3e7fa8c) 的 BL，作为新区域锚
"""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)


def read_text(path, fat, size):
    with open(path, 'rb') as f:
        f.seek(fat)
        return f.read(size)


old_text = read_text('/tmp/wxrelocate/wechat_4_1_11.dylib', 0xa344000, 0x8f2c000)
new_text = read_text('/Applications/wechat.app/Contents/Resources/wechat.dylib', 0xaab0000, 0x9694000)


def disasm(text, off, size):
    return list(md.disasm(text[off:off + size], off))


def parse_imm(token):
    token = token.strip().lstrip('#')
    return int(token, 16) if token.lower().startswith('0x') else int(token)


def vtable_written(insns, text):
    """找 adrp+add 随后 str Xn,[x0] 的 vtable 值。"""
    results = []
    for i in range(len(insns) - 2):
        a, b, c = insns[i], insns[i + 1], insns[i + 2]
        if a.mnemonic == 'adrp' and b.mnemonic == 'add' and c.mnemonic == 'str':
            try:
                parts_a = [p.strip() for p in a.op_str.split(',')]
                parts_b = [p.strip() for p in b.op_str.split(',')]
                parts_c = [p.strip() for p in c.op_str.split(',')]
                if len(parts_a) == 3 and len(parts_b) == 3 and len(parts_c) == 3 \
                        and parts_b[1] == parts_a[0] and parts_c[1] == parts_b[0] \
                        and parts_c[2] == '[x0]':
                    page = parse_imm(parts_a[2])
                    disp = parse_imm(parts_b[2])
                    results.append((a.address, page + disp))
            except (ValueError, IndexError):
                continue
    return results


print('== 1) PayloadCtor vtable 提取 ==')
old_ctor = disasm(old_text, 0x3ebd8a8, 0x100)
new_ctor = disasm(new_text, 0x430a354, 0x100)
old_vt = vtable_written(old_ctor, old_text)
new_vt = vtable_written(new_ctor, new_text)
print('旧 ctor 写入 vtable:', [(hex(a), hex(v)) for a, v in old_vt])
print('新 ctor 写入 vtable:', [(hex(a), hex(v)) for a, v in new_vt])
# 旧 dtor 自己写的 vtable
old_dtor = disasm(old_text, 0x3ebf130, 0x60)
print('旧 dtor 写入 vtable:', [(hex(a), hex(v)) for a, v in vtable_written(old_dtor, old_text)])

if new_vt:
    target_vt = new_vt[0][1]
    print(f'\n扫描新二进制中写 vtable {hex(target_vt)} 的位置（限 0x42f0000-0x4320000 邻域）:')
    hits = []
    insns = disasm(new_text, 0x42f0000, 0x30000)
    for i in range(len(insns) - 2):
        a, b, c = insns[i], insns[i + 1], insns[i + 2]
        if a.mnemonic == 'adrp' and b.mnemonic == 'add' and c.mnemonic == 'str':
            try:
                parts_a = [p.strip() for p in a.op_str.split(',')]
                parts_b = [p.strip() for p in b.op_str.split(',')]
                parts_c = [p.strip() for p in c.op_str.split(',')]
                if len(parts_a) == 3 and len(parts_b) == 3 and len(parts_c) == 3 \
                        and parts_b[1] == parts_a[0] and parts_c[1] == parts_b[0] and parts_c[2] == '[x0]':
                    page = parse_imm(parts_a[2])
                    disp = parse_imm(parts_b[2])
                    if page + disp == target_vt:
                        hits.append(a.address)
            except (ValueError, IndexError):
                continue
    print('写同 vtable 的位置:', [hex(h) for h in hits])

print('\n== 2) 旧 Encoder 反汇编 (0x2a35c48, 到 0x2a35cf0) ==')
for insn in disasm(old_text, 0x2a35c48, 0xa8):
    print(f'{hex(insn.address)}: {insn.mnemonic} {insn.op_str}')

print('\n== 3) 旧 req2buf 区域内 BL 目标 ==')
region = disasm(old_text, 0x3e58c00, 0x2400)
for insn in region:
    if insn.mnemonic == 'bl':
        try:
            target = parse_imm(insn.op_str)
            if 0x3e7f800 <= target <= 0x3e80000:
                print(f'{hex(insn.address)}: bl {hex(target)} (AutoBuffer 区)')
        except ValueError:
            pass
