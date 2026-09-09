#!/usr/bin/env python3
"""v7：三个缺口函数的最终定位。
A) Encoder：新二进制中调用 autoBufferWrite(0x43084c0) 的函数，按形状过滤
B) PayloadDtor：SendAsync 新旧 BL 目标序列对齐，3 个 dtor 调用点投票
C) Req2Buf：新二进制中调用 AutoBufferLength(0x4308564) 的聚簇 = 新 req2buf 区，
   对旧区域做 DP 对齐映射 Req2Buf/Enter/blrX8/Exit
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
OLD, NEW = old_text, new_text


def disasm(text, off, size):
    return list(md.disasm(text[off:off + size], off))


def parse_imm(token):
    token = token.strip().lstrip('#')
    return int(token, 16) if token.lower().startswith('0x') else int(token)


def bl_target(insn):
    if insn.mnemonic != 'bl':
        return None
    try:
        return parse_imm(insn.op_str)
    except ValueError:
        return None


# 已知映射（旧 → 新）
KNOWN = {
    0x3e7fa8c: 0x43084c0,   # autoBufferWriteFunc
    0x3e7fb30: 0x4308564,   # realTextAutoBufferLength
    0x3e7faf0: 0x4308524,   # realTextAutoBufferData
    0x5256c98: 0x5705bdc,   # realTextParseFromArray
    0x3ebd8a8: 0x430a354,   # payloadCtor
}
NEW2OLD = {v: k for k, v in KNOWN.items()}

print('== A) Encoder：调用 autoBufferWrite 的新函数 ==')
# 旧 Encoder 特征: prologue sub sp,#0x40 + stp x20,x19 + 两个关键 BL + 返回 1
cand_regions = []
# 先找新二进制全部 BL->0x43084c0 的位置（扫描预测邻域 0x1f00000-0x2400000 与全局二次筛选太慢，先全扫一次收集）
hits = []
n = len(NEW)
i = 0
words = struct.iter_unpack  # 不用
import array
arr = array.array('I')
# 直接扫描字
NEW_WORDS = None
from array import array as A
wa = A('I')
# 逐块扫描避免内存翻倍——文件 150MB 可接受
with open('/Applications/wechat.app/Contents/Resources/wechat.dylib', 'rb') as f:
    f.seek(0xaab0000)
    raw = f.read(0x9694000)
wa.frombytes(raw)
import sys
if sys.byteorder != 'little':
    wa.byteswap()

targets_of_interest = {0x43084c0, 0x4308564, 0x4308524}
bl_sites = {t: [] for t in targets_of_interest}
for idx in range(len(wa)):
    w = wa[idx]
    if (w & 0xFC000000) != 0x94000000:
        continue
    imm = w & 0x03FFFFFF
    if imm & 0x02000000:
        imm -= 0x04000000
    t = idx * 4 + imm * 4
    if t in bl_sites:
        bl_sites[t].append(idx * 4)

print(f'BL->autoBufferWrite: {len(bl_sites[0x43084c0])} 处, BL->autoBufferLength: {len(bl_sites[0x4308564])} 处')

# Encoder 候选：BL->write 的位置，向上回看 0x100 找函数头（sub sp/stp 序列）
encoder_candidates = []
for site in bl_sites[0x43084c0]:
    head = disasm(NEW, site - 0x120, 0x130)
    # 找 sub sp 序列
    for j, insn in enumerate(head):
        if insn.mnemonic == 'sub' and insn.op_str.startswith('sp, sp, #0x40'):
            start = insn.address
            seg = disasm(NEW, start, 0x120)
            mn = [x.mnemonic for x in seg[:4]]
            if mn[:2] == ['sub', 'stp']:
                has_bl_proto = any(bl_target(x) and 0x5700000 < bl_target(x) < 0x5710000 for x in seg)
                encoder_candidates.append((start, site, has_bl_proto))
print('Encoder 候选（sub sp,#0x40 开头 + 调 autoBufferWrite）:')
for start, site, pb in encoder_candidates:
    print(f'  函数头 {hex(start)}  BL@{hex(site)}  邻近protobuf调用={pb}')

print('\n== C) req2buf：BL->autoBufferLength 聚簇 ==')
sites = bl_sites[0x4308564]
clusters = []
cur = [sites[0]]
for s in sites[1:]:
    if s - cur[-1] < 0x800:
        cur.append(s)
    else:
        if len(cur) >= 3:
            clusters.append(cur)
        cur = [s]
if len(cur) >= 3:
    clusters.append(cur)
for c in clusters:
    print(f'  簇: {len(c)} 个调用点 {hex(c[0])}..{hex(c[-1])}')
