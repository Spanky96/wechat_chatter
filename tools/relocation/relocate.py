#!/usr/bin/env python3
"""把 4.1.11 的函数偏移重定位到 4.1.13：反汇编旧函数生成位级通配模式，在新二进制唯一匹配。

用法: python3 relocate.py [strict|relaxed]
"""
import json
import struct
import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

OLD_BIN = '/tmp/wxrelocate/wechat_4_1_11.dylib'
NEW_BIN = '/Applications/wechat.app/Contents/Resources/wechat.dylib'
OLD_JSON = '/Users/yangyiming/Documents/mydev/wechat_chatter/wechat_version/4_1_11_53_mac.json'
OLD_FAT = 0xa344000
NEW_FAT = 0xaab0000
NEW_TEXT_SIZE = 0x9694000
WINDOW_INSNS = 28

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = False


def load_arm64_text(path, fat_off, text_size):
    with open(path, 'rb') as f:
        f.seek(fat_off)
        return f.read(text_size)


def build_pattern(code_bytes, relaxed=False, skip=0):
    """返回 (mask_bits, bytes) 列表；mask 位=1 表示该位必须匹配。skip 跳过前 N 条指令。"""
    insns = list(md.disasm(code_bytes, 0))
    pattern = []
    for insn in insns[skip:skip + WINDOW_INSNS]:
        word = struct.unpack_from('<I', insn.bytes, 0)[0]
        m = 0xFFFFFFFF
        mne = insn.mnemonic
        if mne == 'adrp':
            m = 0x8000001F & ~0x000000E0  # 位31 + 位4-0(Rd)，imm 全屏蔽
        elif mne in ('b', 'bl'):
            m = 0xFC000000  # 只保留 opcode，imm26 屏蔽
        elif mne == 'b.cond' or mne.startswith('cbz') or mne.startswith('cbnz'):
            m = 0xFF00001F & ~0x00FFFFE0  # 保留 opcode高位与 Rt，imm19 屏蔽
        elif mne.startswith('tbz') or mne.startswith('tbnz'):
            m = 0xFF80001F & ~0x007FFFE0
        elif relaxed:
            if mne in ('ldr', 'str', 'ldur', 'stur') and '[' in insn.op_str:
                m = 0xFFC003FF  # 宽松：仅屏蔽 imm12（位21-10），保留 opcode/Rn/Rt
            elif mne.startswith('mov') or mne == 'movk':
                m = 0xFF00000F & ~0x001FFFE0  # 屏蔽 imm16
            elif mne == 'add' and '#' in insn.op_str:
                m = 0xFFC003FF  # 仅屏蔽 imm12，保留 opcode/Rn/Rd
        pattern.append((word, m))
    return pattern, len(insns)


def masked_equal(pattern, code, at):
    for i, (word, mask) in enumerate(pattern):
        w = struct.unpack_from('<I', code, at + i * 4)[0]
        if (w & mask) != (word & mask):
            return False
    return True


def concrete_anchor(pattern):
    """找最长的连续全具体指令段作为 bytes.find 锚点。"""
    best_run, best_start, run = [], 0, []
    for i, (word, mask) in enumerate(pattern):
        if mask == 0xFFFFFFFF:
            run.append((i, word))
        else:
            if len(run) > len(best_run):
                best_run, best_start = run, run[0][0] if run else 0
            run = []
    if len(run) > len(best_run):
        best_run, best_start = run, run[0][0] if run else 0
    if not best_run:
        return None
    needle = b''.join(struct.pack('<I', w) for _, w in best_run)
    return best_start, needle


def search(pattern, new_text):
    anchor = concrete_anchor(pattern)
    hits = []
    if anchor and len(anchor[1]) >= 12:
        start, needle = anchor
        pos = 0
        while True:
            idx = new_text.find(needle, pos)
            if idx < 0:
                break
            pos = idx + 1
            at = idx - start * 4
            if at < 0 or at + len(pattern) * 4 > len(new_text):
                continue
            if (idx & 3) == 0 and masked_equal(pattern, new_text, at):
                hits.append(at)
                if len(hits) > 20:
                    return hits
    else:
        # 无长锚点：4 字节对齐全扫描（慢，函数少时可行）
        for at in range(0, len(new_text) - len(pattern) * 4, 4):
            if masked_equal(pattern, new_text, at):
                hits.append(at)
                if len(hits) > 20:
                    return hits
    return hits


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else 'strict'
    relaxed = mode in ('relaxed', 'relaxed2')
    old_text = load_arm64_text(OLD_BIN, OLD_FAT, 0x8f2c000)
    new_text = load_arm64_text(NEW_BIN, NEW_FAT, NEW_TEXT_SIZE)
    offsets = json.load(open(OLD_JSON))
    results = {}
    report = []
    for name, old_off in offsets.items():
        old = int(old_off, 16) if isinstance(old_off, str) else int(old_off)
        if old >= 0x8f2c000:
            results[name] = {'old': hex(old), 'new': None, 'status': 'OLD_OFFSET_OUT_OF_RANGE'}
            continue
        code = old_text[old:old + 64 + 64 + WINDOW_INSNS * 4]
        # 窗口滑动：跳过前 0..8 条指令依次尝试（编译器常在函数头插入/调整指令）
        best = None
        for skip in range(0, 9):
            pattern, n_insns = build_pattern(code, relaxed, skip)
            if len(pattern) < 6:
                continue
            hits = search(pattern, new_text)
            if len(hits) == 1:
                best = (hits[0], 'UNIQUE', skip)
                break
            if len(hits) > 1:
                # 尾部复核：用窗口之后的严格模式片段过滤候选
                tail_pattern, _ = build_pattern(code, False, skip + WINDOW_INSNS)
                if len(tail_pattern) >= 4:
                    verified = [h for h in hits
                                if h + (skip + WINDOW_INSNS) * 4 + len(tail_pattern) * 4 <= len(new_text)
                                and masked_equal(tail_pattern, new_text, h + WINDOW_INSNS * 4)]
                    if len(verified) == 1:
                        best = (verified[0], 'UNIQUE+TAIL', skip)
                        break
                if best is None:
                    best = (hits, f'AMBIGUOUS({len(hits)})', skip)
        if best is None:
            status, new_off, skip = 'NOT_FOUND', None, '-'
        else:
            new_off, status, skip = best
        results[name] = {
            'old': hex(old),
            'new': hex(new_off) if isinstance(new_off, int) else new_off,
            'status': status,
            'skip': skip
        }
        report.append(f"{status:16} skip={skip} {name:36} {hex(old)} -> " +
                      (hex(new_off) if isinstance(new_off, int) else str((new_off or [])[:5])))
    out = f'/tmp/wxrelocate/relocated_{mode}.json'
    json.dump(results, open(out, 'w'), indent=1)
    print('\n'.join(report))
    ok = sum(1 for r in results.values() if r['status'] == 'UNIQUE')
    print(f'\n== [{mode}] 唯一命中 {ok}/{len(results)}，明细在 {out} ==')


if __name__ == '__main__':
    main()
