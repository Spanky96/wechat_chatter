#!/usr/bin/env python3
"""v5b：修 ADRP 解析 + 掩码级 ctor 复核。"""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from relocate import build_pattern, masked_equal

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
OLD_BIN = '/tmp/wxrelocate/wechat_4_1_11.dylib'
NEW_BIN = '/Applications/wechat.app/Contents/Resources/wechat.dylib'
OLD_FAT, NEW_FAT = 0xa344000, 0xaab0000


def read_text(path, fat, size):
    with open(path, 'rb') as f:
        f.seek(fat)
        return f.read(size)


old_text = read_text(OLD_BIN, OLD_FAT, 0x8f2c000)
new_text = read_text(NEW_BIN, NEW_FAT, 0x9694000)


def parse_imm(token):
    token = token.strip().lstrip('#')
    return int(token, 16) if token.lower().startswith('0x') else int(token)


def adrp_strings(text, start, size, label):
    insns = list(md.disasm(text[start:start + size], start))
    results = []
    for i in range(len(insns) - 1):
        a, b = insns[i], insns[i + 1]
        if a.mnemonic != 'adrp' or b.mnemonic != 'add':
            continue
        try:
            parts_a = [p.strip() for p in a.op_str.split(',')]
            parts_b = [p.strip() for p in b.op_str.split(',')]
            if len(parts_a) != 3 or len(parts_b) != 3:
                continue
            if parts_b[1] != parts_a[0]:
                continue
            page = parse_imm(parts_a[2])
            disp = parse_imm(parts_b[2])
            target = page + disp
            if target < 0 or target + 8 >= len(text):
                continue
            raw = text[target:target + 80]
            s = raw.split(b'\0')[0]
            if len(s) >= 5 and all(32 <= c < 127 for c in s):
                results.append((a.address, target, s.decode()))
        except (ValueError, IndexError):
            continue
    print(f'--- {label}: {len(results)} 条字符串引用 ---')
    for addr, target, s in results[:25]:
        print(f'    {hex(addr)} -> {hex(target)}: {s[:60]}')
    return results


print('== ctor 掩码级复核 ==')
pat, _ = build_pattern(old_text[0x2a35ac8:0x2a35ac8 + 0x120], True, 0)
print('新 0x21f40f0 掩码匹配:', masked_equal(pat, new_text, 0x21f40f0))

print('\n== ADRP 字符串引用（修复解析） ==')
adrp_strings(old_text, 0x3e58e44, 0x1000, 'req2buf 簇')
adrp_strings(old_text, 0x529bd7c, 0x300, 'uploadImage')
adrp_strings(old_text, 0x535ea98, 0x300, 'downloadFile')
adrp_strings(old_text, 0x53c0004, 0x300, 'downloadImag')
adrp_strings(old_text, 0x5378a18, 0x300, 'downloadVideo')
adrp_strings(old_text, 0x3e14ff8, 0x400, 'uploadGetCallbackWrapperFunc')
adrp_strings(old_text, 0x3e1617c, 0x200, 'uploadOnCompleteFunc')
adrp_strings(old_text, 0x525b2d8, 0x200, 'uploadOnComplete')
