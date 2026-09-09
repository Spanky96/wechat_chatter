#!/usr/bin/env python3
"""第二阶段：联合一致性 + 邻域约束。
1) AMBIGUOUS 簇：按函数间旧偏移间距，要求候选组合的新间距近似不变 → 联合求解。
2) NOT_FOUND：用最近的 UNIQUE 锚点预测位置，在 ±窗口内做"操作码+寄存器结构"级匹配。
"""
import json
from relocate import (
    md, load_arm64_text, build_pattern, masked_equal, search,
    OLD_JSON, OLD_FAT, NEW_FAT, NEW_TEXT_SIZE, WINDOW_INSNS
)
import struct

OLD_BIN = '/tmp/wxrelocate/wechat_4_1_11.dylib'
NEW_BIN = '/Applications/wechat.app/Contents/Resources/wechat.dylib'

old_text = load_arm64_text(OLD_BIN, OLD_FAT, 0x8f2c000)
new_text = load_arm64_text(NEW_BIN, NEW_FAT, NEW_TEXT_SIZE)
stage1 = json.load(open('/tmp/wxrelocate/relocated_relaxed.json'))


def structural_pattern(code, skip=0):
    """结构级模式：保留操作码与寄存器分配，屏蔽全部立即数/内存偏移。"""
    insns = list(md.disasm(code, 0))
    pattern = []
    for insn in insns[skip:skip + WINDOW_INSNS]:
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
        elif mne in ('ldr', 'str', 'ldur', 'stur') and '[' in insn.op_str:
            m = 0xFFC003FF
        elif mne.startswith('mov') or mne == 'movk':
            m = 0xFF00000F & ~0x001FFFE0
        elif mne == 'add' and '#' in insn.op_str:
            m = 0xFFC003FF
        pattern.append((word, m))
    return pattern


def hits_in_window(pattern, center, radius):
    lo = max(0, center - radius)
    hi = min(len(new_text), center + radius)
    hits = []
    seg = new_text[lo:hi]
    for at in range(0, len(seg) - len(pattern) * 4, 4):
        if masked_equal(pattern, seg, at):
            hits.append(lo + at)
    return hits


results = dict(stage1)

# ---------- 1) AMBIGUOUS 簇联合一致性 ----------
ambiguous = {n: r for n, r in stage1.items() if r['status'].startswith('AMBIGUOUS') and isinstance(r['new'], list)}
if len(ambiguous) >= 2:
    names = sorted(ambiguous, key=lambda n: int(stage1[n]['old'], 16))
    base = names[0]
    base_old = int(stage1[base]['old'], 16)
    solved = {}
    for base_cand in ambiguous[base]['new']:
        score, assignment = 0, {base: base_cand}
        for other in names[1:]:
            want = int(stage1[other]['old'], 16) - base_old
            matches = [c for c in ambiguous[other]['new'] if abs(c - base_cand - want) <= 0x600]
            if len(matches) == 1:
                assignment[other] = matches[0]
                score += 1
        if score > len(solved.get('assign', {}).get('x', [])) or not solved:
            solved = {'base': base_cand, 'assign': assignment, 'score': score}
    for name, new_off in solved['assign'].items():
        results[name] = {'old': stage1[name]['old'], 'new': hex(new_off), 'status': f"JOINT(score {solved['score']}/{len(names)-1})", 'skip': stage1[name].get('skip')}
    print(f"[联合求解] 基点 {base} @ {hex(solved['base'])} 一致 {solved['score']}/{len(names)-1}")
    for name in names:
        print(f"  {results[name]['status']:20} {name:36} -> {results[name]['new']}")

# ---------- 2) NOT_FOUND 邻域结构搜索 ----------
uniques = sorted(
    [(int(r['old'], 16), int(r['new'], 16)) for r in stage1.values() if r['status'].startswith('UNIQUE')]
)
for name, r in stage1.items():
    if r['status'] != 'NOT_FOUND':
        continue
    old = int(r['old'], 16)
    prev = max((u for u in uniques if u[0] < old), default=None)
    nxt = min((u for u in uniques if u[0] > old), default=None)
    if not prev and not nxt:
        print(f"[邻域失败] {name} 无锚点")
        continue
    if prev and nxt:
        t = (old - prev[0]) / (nxt[0] - prev[0])
        predicted = int(prev[1] + t * (nxt[1] - prev[1]))
        radius = 0x40000
    else:
        anchor = prev or nxt
        predicted = old + (anchor[1] - anchor[0])
        radius = 0x60000
    code = old_text[old:old + 64 + WINDOW_INSNS * 4]
    found = None
    for skip in range(0, 9):
        pattern = structural_pattern(code, skip)
        if len(pattern) < 8:
            continue
        hits = hits_in_window(pattern, predicted, radius)
        if len(hits) == 1:
            found = (hits[0], f'NEIGHBOR+STRUCT(skip {skip})')
            break
        if len(hits) > 1 and found is None:
            found = (hits, f'NEIGHBOR_AMBIGUOUS({len(hits)})')
    if isinstance(found and found[0], int):
        results[name] = {'old': r['old'], 'new': hex(found[0]), 'status': found[1], 'skip': 0}
        print(f"[邻域结构] {found[1]:26} {name:36} -> {hex(found[0])} (预测 {hex(predicted)})")
    else:
        print(f"[邻域失败] {name:36} 预测 {hex(predicted)} {'候选 ' + str([hex(h) for h in found[0][:4]]) if found else '无'}")

json.dump(results, open('/tmp/wxrelocate/relocated_stage2.json', 'w'), indent=1)
ok = sum(1 for r in results.values() if r['status'] not in ('NOT_FOUND',) and not str(r['status']).startswith(('AMBIGUOUS', 'NEIGHBOR_AMBIGUOUS')))
print(f'\n== 二阶段后有效命中 {ok}/{len(results)} ==')
