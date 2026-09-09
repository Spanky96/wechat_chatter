#!/usr/bin/env python3
"""第四阶段：函数体对齐迁移 BL 调用点。
old realTextSendAsync(0x2a34cbc) -> new 0x21f3380（联合求解结果）。
用带通配掩码的指令序列 DP 对齐新旧函数体，把旧 BL(+0xcc8 ctor / +0xee8,+0xf30,+0xf70 dtor)
映射到新 BL，读出新目标。
"""
import struct
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from relocate import build_pattern

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

OLD_BIN = '/tmp/wxrelocate/wechat_4_1_11.dylib'
NEW_BIN = '/Applications/wechat.app/Contents/Resources/wechat.dylib'
OLD_FAT, NEW_FAT = 0xa344000, 0xaab0000


def read(path, fat, off, size):
    with open(path, 'rb') as f:
        f.seek(fat + off)
        return f.read(size)


OLD_START, NEW_START = 0x2a34cbc, 0x21f3380
BODY = 0x1100  # 覆盖 +0xf70 之后

old_code = read(OLD_BIN, OLD_FAT, OLD_START, BODY)
new_code = read(NEW_BIN, NEW_FAT, NEW_START, BODY)

old_insns = list(md.disasm(old_code, 0))
new_insns = list(md.disasm(new_code, 0))
print(f'旧指令数 {len(old_insns)}, 新指令数 {len(new_insns)}')


def feat(insns, i):
    """结构特征：助记符 + 操作数形状（屏蔽立即数）。"""
    word = struct.unpack_from('<I', insns[i].bytes, 0)[0]
    pat = build_pattern(insns[i].bytes, False, 0)  # 不适用——直接手写
    return None


def mask_of(insn):
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
    return word & m, m


def eq(i, j):
    wi, _ = mask_of(old_insns[i])
    wj, _ = mask_of(new_insns[j])
    mi = mask_of(old_insns[i])[1]
    return (wi & mi) == (wj & mi)


# DP 对齐（Needleman-Wunsch 简化版）
n, m = len(old_insns), len(new_insns)
GAP, MATCH, MISS = -1, 2, -2
import sys
sys.setrecursionlimit(10000)
dp = [[0] * (m + 1) for _ in range(n + 1)]
for i in range(1, n + 1):
    dp[i][0] = dp[i - 1][0] + GAP
for j in range(1, m + 1):
    dp[0][j] = dp[0][j - 1] + GAP
for i in range(1, n + 1):
    row, prev = dp[i], dp[i - 1]
    for j in range(1, m + 1):
        best = prev[j - 1] + (MATCH if eq(i - 1, j - 1) else MISS)
        v = prev[j] + GAP
        if v > best:
            best = v
        v = row[j - 1] + GAP
        if v > best:
            best = v
        row[j] = best

# 回溯得到对齐映射
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
print(f'对齐指令 {len(mapping)}，其中结构匹配 {matched}')


def bl_target_rel(insn, pc):
    word = struct.unpack_from('<I', insn.bytes, 0)[0]
    if (word & 0xFC000000) != 0x94000000:
        return None
    imm = word & 0x03FFFFFF
    if imm & 0x02000000:
        imm -= 0x04000000
    return pc + imm * 4


for label, rel in [('RequestCtor', 0xcc8), ('PayloadDtor#1', 0xee8), ('PayloadDtor#2', 0xf30), ('PayloadDtor#3', 0xf70)]:
    idx = rel // 4
    if idx not in mapping:
        print(f'{label}: 旧调用点 +{hex(rel)} 未对齐')
        continue
    jdx = mapping[idx]
    old_t = bl_target_rel(old_insns[idx], idx * 4)
    new_t = bl_target_rel(new_insns[jdx], jdx * 4)
    is_bl_old = old_t is not None
    is_bl_new = new_t is not None
    print(f'{label}: 旧BL@+{hex(idx*4)}(目标{hex(OLD_START+old_t) if old_t is not None else "?"}) '
          f'-> 新BL@+{hex(jdx*4)} ({"BL✓" if is_bl_new else "不是BL!"}) '
          f'新目标 {hex(NEW_START+new_t) if new_t is not None else "?"}')
