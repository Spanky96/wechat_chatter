#!/usr/bin/env python3
"""第五阶段：
1) 结构比对验证 RequestCtor 候选
2) 在 ctor..response 精确区间内结构搜索 realTextEncoder
3) 旧 dtor 形状 vs 候选 0x4302a1c
4) ADRP+ADD 字符串引用提取（req2buf 簇 + 上传/下载簇）
"""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from relocate import build_pattern, masked_equal

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
OLD_BIN = '/tmp/wxrelocate/wechat_4_1_11.dylib'
NEW_BIN = '/Applications/wechat.app/Contents/Resources/wechat.dylib'
OLD_FAT, NEW_FAT = 0xa344000, 0xaab0000
OLD_TEXT_SIZE, NEW_TEXT_SIZE = 0x8f2c000, 0x9694000


def read_text(path, fat, size):
    with open(path, 'rb') as f:
        f.seek(fat)
        return f.read(size)


old_text = read_text(OLD_BIN, OLD_FAT, OLD_TEXT_SIZE)
new_text = read_text(NEW_BIN, NEW_FAT, NEW_TEXT_SIZE)


def disasm(text, off, size):
    return list(md.disasm(text[off:off + size], off))


def struct_match_score(old_off, new_off, size=0x100):
    a = disasm(old_text, old_off, size)
    b = disasm(new_text, new_off, size)
    n = min(len(a), len(b))
    hit = 0
    for i in range(n):
        wa = struct.unpack_from('<I', a[i].bytes, 0)[0]
        wb = struct.unpack_from('<I', b[i].bytes, 0)[0]
        if wa == wb:
            hit += 1
    return hit, n


print('== 1) RequestCtor 验证 (旧 0x2a35ac8 vs 新 0x21f40f0) ==')
hit, n = struct_match_score(0x2a35ac8, 0x21f40f0, 0x120)
print(f'完全相同指令 {hit}/{n}')

print('\n== 2) Encoder 精确区间搜索 (0x21f40f0, 0x21f42a4) ==')
encoder_old = 0x2a35c48
code = old_text[encoder_old:encoder_old + 0x200]
found = []
for skip in range(0, 6):
    pattern, _ = build_pattern(code, True, skip)
    if len(pattern) < 6:
        continue
    for at in range(0x21f40f0, 0x21f42a4 - len(pattern) * 4, 4):
        if masked_equal(pattern, new_text, at):
            found.append((skip, at))
print('Encoder 候选:', [(s, hex(a)) for s, a in found[:10]] or '无')

print('\n== 3) 旧 PayloadDtor 形状 vs 0x4302a1c ==')
for off, text, label in [(0x3ebf130, old_text, '旧dtor'), (0x4302a1c, new_text, '候选')]:
    print(f'{label}:')
    for insn in disasm(text, off, 0x40)[:8]:
        print(f'    {hex(insn.address)}: {insn.mnemonic} {insn.op_str}')

print('\n== 4) ADRP+ADD 字符串引用 ==')


def adrp_strings(text, start, size, label):
    """提取区域内 ADRP+ADD 指向的字符串。"""
    insns = disasm(text, start, size)
    results = []
    for i in range(len(insns) - 1):
        a, b = insns[i], insns[i + 1]
        if a.mnemonic != 'adrp' or b.mnemonic != 'add':
            continue
        try:
            adrp_reg = a.op_str.split(', ')[0]
            add_parts = b.op_str.split(', ')
            if add_parts[0] != adrp_reg or len(add_parts) < 3 or not add_parts[2].startswith('#'):
                continue
            page = int(a.op_str.split(', ')[2], 16)
            disp = int(add_parts[2][1:], 16)
            target = page + disp
            if target + 8 >= len(text):
                continue
            raw = text[target:target + 64]
            s = raw.split(b'\0')[0]
            if len(s) >= 5 and all(32 <= c < 127 for c in s):
                results.append((a.address, target, s.decode()))
        except (ValueError, IndexError):
            continue
    print(f'--- {label} ---')
    for addr, target, s in results[:20]:
        print(f'    {hex(addr)} -> {hex(target)}: {s[:56]}')
    return results


adrp_strings(old_text, 0x3e58e44, 0x1000, 'req2buf 簇 (0x3e58e44..0x3e59e44)')
adrp_strings(old_text, 0x529bd7c, 0x300, 'uploadImage')
adrp_strings(old_text, 0x535ea98, 0x300, 'downloadFile')
adrp_strings(old_text, 0x53c0004, 0x300, 'downloadImag')
adrp_strings(old_text, 0x5378a18, 0x300, 'downloadVideo')
adrp_strings(old_text, 0x3e14ff8, 0x400, 'uploadGetCallbackWrapperFunc')
adrp_strings(old_text, 0x3e1617c, 0x200, 'uploadOnCompleteFunc')
