'use strict';
// ============================================================================
// 只读观察脚本 v2 —— 仅函数入口 hook (ARM64e / PAC 安全版)
//
// v1 在函数中段 (blr x8 @0x3e58f10) 与 epilogue 中段 (0x3e59dc4) 挂 hook,
// 破坏了带 PAC 签名的控制流, 导致微信在 mars::stn 线程 Instruction Abort 崩溃
// (WeChat-2026-07-30-163638.ips, pc-stripped = base+0x3e59dac)。
//
// 本版只挂两个真正的函数入口 (Frida 序言 hook 对 PAC 处理成熟):
//   1. MMStartTask  0x5120fd8
//   2. Req2Buf      0x3e58e44
// 所需信息全部在 Req2Buf 入口处读取:
//   - 遍历 session+0x60 的任务 map, 记录所有 key (用于看节点生命周期)
//   - 对命中当前 taskId 的节点, dump 其真实 request 对象布局与 vtable
//   - vtable[2] (=[vt+0x10]) 即被调用的 protobuf 编码器, 无需 hook 它
//
// 全部读取用 try/catch 直读 (Frida 会在缺页时抛 JS 异常而非杀进程)。
// 不写任何内存, 不改任何寄存器, 不 NativeFunction 调用。
// ============================================================================

var OFF = {
    startTask: 0x5120fd8,    // MMStartTask(x0=manager, x1=task) 函数入口
    req2bufEnter: 0x3e58e44  // Req2Buf(x0=session, x1=taskId, x4=?) 函数入口
};

// 关键: 必须选 Resources 下那个 ~150MB 的真身。
// Frameworks 下存在同名 wechat.dylib 但只有 16KB 的桩, 选错它会让所有
// hook 落到 (桩base + 大偏移) 的全 0 区域, 静默失效、抓不到任何东西。
var mods = Process.enumerateModules().filter(function (m) {
    return m.path.indexOf('wechat.dylib') >= 0;
});
var mod = mods.filter(function (m) {
    return m.path.indexOf('/Contents/Resources/wechat.dylib') >= 0;
})[0] || mods.sort(function (a, b) { return b.size - a.size; })[0];
if (!mod || mod.size < 0x6000000) {
    throw new Error('未找到真正的 Resources/wechat.dylib (size=' + (mod && mod.size) + ')');
}
var base = mod.base;
console.log('[OBS2] 真身 wechat.dylib base=' + base + ' size=0x' + mod.size.toString(16) + ' path=' + mod.path);

function hex(n) { return '0x' + n.toString(16); }

function rp(p) { try { return p.readPointer(); } catch (e) { return null; } }
function ru32(p) { try { return p.readU32(); } catch (e) { return null; } }
function ru64(p) { try { return p.readU64(); } catch (e) { return null; } }
function ru8(p) { try { return p.readU8(); } catch (e) { return null; } }

// libc++ std::string 读取 (短串内联 / 长串堆)
function readStr(p) {
    var b0 = ru8(p);
    if (b0 === null) return '<bad>';
    try {
        if ((b0 & 1) === 0) {
            var n = b0 >> 1;
            if (n === 0) return '""';
            return JSON.stringify(p.add(1).readUtf8String(n));
        }
        var size = p.add(8).readU64().toNumber();
        var data = p.add(16).readPointer();
        return JSON.stringify(data.readUtf8String(size));
    } catch (e) { return '<bad:' + e + '>'; }
}

// 把 obj 前 len 字节按 8 字节一行 dump, 同时标出像指针的槽位
function dumpObj(obj, len) {
    var lines = [];
    for (var i = 0; i < len; i += 8) {
        var v = ru64(obj.add(i));
        if (v === null) { lines.push('  +' + hex(i) + ' = <unreadable>'); continue; }
        var hexv = v.toString(16).padStart(16, '0');
        var note = '';
        var asPtr = rp(obj.add(i));
        if (asPtr && !asPtr.isNull()) {
            // 试探它指向的是不是字符串 (cgi 等)
            var s = readStr(obj.add(i));
            if (s && s !== '<bad>' && s !== '""' && /^"[\x20-\x7e]/.test(s)) {
                note = '  -> str ' + s;
            } else {
                var p0 = rp(asPtr);
                if (p0 && !p0.isNull()) note = '  -> ptr ' + asPtr + ' (*=' + p0 + ')';
                else note = '  -> ptr ' + asPtr;
            }
        }
        lines.push('  +' + hex(i) + ' = ' + hexv + note);
    }
    return lines.join('\n');
}

function describeRequest(obj) {
    if (!obj) return 'obj=<null>';
    var vt = rp(obj);
    var lines = ['request obj=' + obj + '  vtable=' + (vt || '<bad>')];
    if (vt && !vt.isNull()) {
        var slots = [];
        for (var s = 0; s < 6; s++) {
            var f = rp(vt.add(s * 8));
            slots.push(f ? ('[' + s + ']=' + f + '(+' + f.sub(base) + ')') : '[' + s + ']=<bad>');
        }
        lines.push('  vtable 槽位(编码器=[2]): ' + slots.join(' '));
    }
    lines.push('  字段 (对照伪造对象: +8=taskId +0xc=类型 +0x10 +0x18=cgi +0x20):');
    lines.push(dumpObj(obj, 0xc0));
    return lines.join('\n');
}

// 遍历 libc++ std::map (红黑树) 的中序; 返回 {keys:[...], nodes:[{key,val,node}]}
function walkMap(rootSlot, maxNodes) {
    var end = rootSlot;
    var root = rp(rootSlot);
    var out = { rootStr: (root || '0x0'), keys: [], nodes: [] };
    if (!root || root.isNull()) return out;
    var stack = [], cur = root, guard = 0;
    while ((cur && !cur.isNull() && !cur.equals(end)) || stack.length) {
        if (++guard > (maxNodes || 200)) { out.keys.push('...截断'); break; }
        if (cur && !cur.isNull() && !cur.equals(end)) {
            stack.push(cur);
            cur = rp(cur); // __left_
        } else {
            cur = stack.pop();
            var key = ru32(cur.add(0x20));
            var val = rp(cur.add(0x28));
            out.keys.push(key);
            out.nodes.push({ key: key, val: val, node: cur });
            cur = rp(cur.add(0x08)); // __right_
        }
    }
    return out;
}

// 任务生命周期: 记录每次 Req2Buf 入口时 map 里出现过的 taskId
var seen = {};

// ---------- Hook 1: MMStartTask 入口 ----------
Interceptor.attach(base.add(OFF.startTask), {
    onEnter: function (args) {
        var x0 = this.context.x0, x1 = this.context.x1;
        var stn = rp(x0.add(0x18));
        var cgi = readStr(x1.add(0x18));
        console.log('\n===== [1] MMStartTask tid=' + this.threadId + ' =====');
        console.log('  manager x0=' + x0 + '  STN=[manager+0x18]=' + stn);
        console.log('  task x1=' + x1 + '  cgi=' + cgi);
    }
});

// ---------- Hook 2: Req2Buf 入口 ----------
Interceptor.attach(base.add(OFF.req2bufEnter), {
    onEnter: function (args) {
        var session = this.context.x0;
        var taskId = this.context.x1.toUInt32();
        seen[taskId] = (seen[taskId] || 0) + 1;
        console.log('\n===== [2] Req2Buf ENTER tid=' + this.threadId + ' =====');
        console.log('  session=' + session + '  taskId(x1)=' + taskId +
            ' (' + hex(taskId) + ')  本ID第' + seen[taskId] + '次');
        var map = walkMap(session.add(0x60));
        console.log('  map根@session+0x60 = ' + map.rootStr +
            '  当前所有key=[' + map.keys.join(',') + ']');
        // dump 命中当前 taskId 的那个真实 request 对象
        var hit = null;
        for (var i = 0; i < map.nodes.length; i++) {
            if (map.nodes[i].key === taskId) { hit = map.nodes[i]; break; }
        }
        if (hit) {
            console.log('  命中节点 node=' + hit.node + ' val(+0x28)=' + hit.val);
            console.log('  ---- 真实 request 对象布局 ----');
            console.log(describeRequest(hit.val));
        } else {
            console.log('  未在 map 中找到 taskId=' + taskId + ' 的节点');
        }
    }
});

console.log('\n[OBS2] 已安装 2 个函数入口 hook (MMStartTask / Req2Buf), 无中段 hook。');
console.log('[OBS2] 请在微信客户端用专用测试会话手动发送文本消息。');
