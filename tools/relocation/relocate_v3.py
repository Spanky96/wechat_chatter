#!/usr/bin/env python3
"""第三阶段：BL 调用引用迁移。
在旧二进制建立 BL xref 索引，找出缺口函数的调用方；
若调用方已被重定位（新旧地址已知），读新调用方的 BL 目标即得被调函数新地址。
"""
import json
import struct
from array import array

OLD_TEXT = None
NEW_TEXT = None

def load(path, fat, size):
    with open(path, 'rb') as f:
        f.seek(fat)
        a = array('I')
        a.frombytes(f.read(size))
    if __import__('sys').byteorder != 'little':
        a.byteswap()
    return a

OLD_TEXT = load('/tmp/wxrelocate/wechat_4_1_11.dylib', 0xa344000, 0x8f2c000)
NEW_TEXT = load('/Applications/wechat.app/Contents/Resources/wechat.dylib', 0xaab0000, 0x9694000)

stage2 = json.load(open('/tmp/wxrelocate/relocated_stage2.json'))
known = {}
for name, r in stage2.items():
    if isinstance(r.get('new'), str) and r['new'].startswith('0x'):
        known[name] = (int(r['old'], 16), int(r['new'], 16))
missing = [name for name, r in stage2.items()
           if r['status'] == 'NOT_FOUND' or (r['status'].startswith(('AMBIGUOUS', 'NEIGHBOR_AMBIG')) and isinstance(r.get('new'), list))]
# 已知函数的旧地址 → 新地址（供调用方对齐）
old2new_by_off = {v[0]: v[1] for v in known.values()}


def bl_target(word, idx):
    """word 是 BL 指令时返回目标地址，否则 None。"""
    if (word & 0xFC000000) != 0x94000000:
        return None
    imm = word & 0x03FFFFFF
    if imm & 0x02000000:
        imm -= 0x04000000
    return idx * 4 + imm * 4


print('== 建立 BL xref 索引（一次全扫） ==')
bl_index = {}
for i, w in enumerate(OLD_TEXT):
    if (w & 0xFC000000) == 0x94000000:
        t = bl_target(w, i)
        if t is not None and 0 < t < len(OLD_TEXT) * 4:
            bl_index.setdefault(t, []).append(i * 4)
print(f'BL 目标数: {len(bl_index)}')

print('\n== 缺口函数的旧 BL 调用方 ==')
for name in sorted(missing):
    target = int(stage2[name]['old'], 16)
    sites = bl_index.get(target, [])
    near_known = []
    for site in sites:
        for kname, (old_off, new_off) in known.items():
            if old_off <= site < old_off + 0x3000:
                near_known.append((site, kname, old_off, new_off))
                break
    print(f"{name:36} 旧={hex(target)} 调用方BL数={len(sites)} 已重定位调用方={len(near_known)}")
    for site, kname, old_off, new_off in near_known[:6]:
        print(f"    调用点 {hex(site)} 在 {kname}(旧{hex(old_off)}→新{hex(new_off)}) 内, BL相对函数头 {hex(site - old_off)}")

with open('/tmp/wxrelocate/bl_index_old.json', 'w') as f:
    json.dump({str(t): v[:200] for t, v in bl_index.items() if len(v) <= 200}, f)
print('\nBL 索引已保存 bl_index_old.json')
