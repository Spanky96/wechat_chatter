'use strict';
throw new Error('[DISABLED] 此脚本包含函数中段 Hook，已确认会破坏 ARM64e/PAC 控制流；请改用 observe_send_safe.js 或 observe_newsend_factory.js');
// 只读观察脚本：记录微信真实发送流程的对象与生命周期。
// 严禁写内存、改寄存器、主动调用微信函数。所有 hook 只读取并打印。
// 用法: frida -p $(pgrep -x WeChat) -l tools/observe_send.js

var OFF = {
    startTask: 0x5120fd8,   // MMStartTask(x0=manager, x1=task)
    req2bufEnter: 0x3e58e44, // Req2Buf 真入口
    mapProbe: 0x3e58ecc,    // map 查找完成, x23=命中节点, x24=end 哨兵(session+0x60)
    blrX8: 0x3e58f10,       // 真正的 blr x8
    req2bufExit: 0x3e59dc4, // epilogue 前最后一条: x23/x24/x25 仍有效
                            // (配置里的 0x3e59de0 在 ldp x24,x23 / ldp x26,x25 之后,
                            //  那里读到的 x25 已经是调用者的值, 不是 taskId)
    buf2Resp: 0x3e7e670,
};

var base = null;
var modules = Process.enumerateModules();
for (var i = 0; i < modules.length; i++) {
    if (modules[i].path.endsWith('/WeChat.app/Contents/Resources/wechat.dylib')) {
        base = modules[i].base;
        break;
    }
}
if (base === null) {
    throw new Error('[OBS] 找不到 wechat.dylib');
}
console.log('[OBS] wechat.dylib base=' + base);

// ---------- 只读工具 ----------
function readable(p) {
    try {
        if (!p || p.isNull()) return false;
        var r = Process.findRangeByAddress(p);
        return r !== null && r.protection.indexOf('r') !== -1;
    } catch (e) {
        return false;
    }
}

function dump(p, len) {
    if (!readable(p)) return '<unreadable ' + p + '>';
    var out = [];
    for (var off = 0; off < len; off += 8) {
        if (!readable(p.add(off))) break;
        try {
            out.push('+0x' + off.toString(16) + '=' + p.add(off).readPointer());
        } catch (e) {
            break;
        }
    }
    return out.join(' ');
}

function cstr(p) {
    try {
        return readable(p) ? p.readUtf8String() : '';
    } catch (e) {
        return '';
    }
}

// 读取 request 对象中已知的关键字段，不做任何写入。
function describeRequest(obj) {
    if (!readable(obj)) return 'obj=<unreadable ' + obj + '>';
    var lines = ['obj=' + obj];
    var vt = null;
    try {
        vt = obj.readPointer();
    } catch (e) {
        return lines.join(' ') + ' vtable=<read fail>';
    }
    lines.push('vtable=' + vt);
    if (readable(vt)) {
        for (var s = 0; s < 6; s++) {
            var slot = vt.add(s * 8);
            if (!readable(slot)) break;
            lines.push('vt[' + s + ']=' + slot.readPointer().sub(base));
        }
    }
    try {
        lines.push('cgi="' + cstr(obj.add(0x18).readPointer()) + '"');
    } catch (e) {}
    try {
        lines.push('a0=' + obj.add(0xa0).readPointer() + ' a8=' + obj.add(0xa8).readPointer());
    } catch (e) {}
    lines.push('raw[0x00-0x40]: ' + dump(obj, 0x40));
    return lines.join(' ');
}

// 中序遍历 libc++ __tree, 只读取节点。
function walkMap(rootSlot) {
    if (!readable(rootSlot)) return '<root slot unreadable>';
    var root;
    try {
        root = rootSlot.readPointer();
    } catch (e) {
        return '<root read fail>';
    }
    if (root.isNull()) return 'root=NULL (空表)';
    var out = ['root=' + root];
    var stack = [root];
    var seen = 0;
    while (stack.length > 0 && seen < 48) {
        var n = stack.pop();
        if (!readable(n) || n.isNull()) continue;
        seen++;
        var key, val;
        try {
            key = n.add(0x20).readU32();
            val = n.add(0x28).readPointer();
        } catch (e) {
            out.push('node=' + n + ' <read fail>');
            continue;
        }
        out.push('node=' + n + ' key=' + key + ' val=' + val +
            ' L=' + n.readPointer() + ' R=' + n.add(0x08).readPointer() +
            ' P=' + n.add(0x10).readPointer() + ' black=' + n.add(0x18).readU8());
        try {
            var l = n.readPointer();
            var r = n.add(0x08).readPointer();
            if (!l.isNull()) stack.push(l);
            if (!r.isNull()) stack.push(r);
        } catch (e) {}
    }
    out.push('nodeCount=' + seen);
    return out.join('\n      ');
}

var ctxByThread = {};

// ---------- Hook 1: MMStartTask 入口 ----------
// 记录长期存活的 manager(x0) 与本次任务描述块(x1)。
Interceptor.attach(base.add(OFF.startTask), {
    onEnter: function (args) {
        var x0 = this.context.x0;
        var x1 = this.context.x1;
        console.log('\n===== [1] MMStartTask tid=' + this.threadId + ' =====');
        console.log('  manager x0=' + x0 + ' task x1=' + x1);
        console.log('  manager[0x18]=' + (readable(x0.add(0x18)) ? x0.add(0x18).readPointer() : '?'));
        console.log('  task raw[0x00-0x60]: ' + dump(x1, 0x60));
        var cgi = '';
        try {
            cgi = cstr(x1.add(0x18).readPointer());
        } catch (e) {}
        console.log('  task cgi="' + cgi + '"');
    }
});

// ---------- Hook 2: Req2Buf 真入口 ----------
// 打印进入时的完整任务表快照 + 本次查找的 taskId。
Interceptor.attach(base.add(OFF.req2bufEnter), {
    onEnter: function (args) {
        var session = this.context.x0;
        var taskId = this.context.x1.toUInt32();
        ctxByThread[this.threadId] = { session: session, taskId: taskId, t0: Date.now() };
        console.log('\n===== [2] Req2Buf ENTER tid=' + this.threadId + ' =====');
        console.log('  session x0=' + session + ' taskId(x1)=' + taskId + ' (0x' + taskId.toString(16) + ')');
        console.log('  任务表 @ session+0x60:\n      ' + walkMap(session.add(0x60)));
    }
});

// ---------- Hook 3: map 查找结束, x23 = 命中节点 ----------
Interceptor.attach(base.add(OFF.mapProbe), {
    onEnter: function (args) {
        var node = this.context.x23;
        var end = this.context.x24;
        var c = ctxByThread[this.threadId];
        console.log('\n===== [3] map lookup done tid=' + this.threadId +
            ' taskId=' + (c ? c.taskId : '?') + ' =====');
        console.log('  x23(node)=' + node + ' x24(end/root-slot)=' + end +
            ' hit=' + (!node.equals(end)));
        if (node.equals(end)) {
            console.log('  未命中: 该 taskId 不在表中, Req2Buf 会直接返回');
            return;
        }
        try {
            console.log('  node key=' + node.add(0x20).readU32() +
                ' value(+0x28)=' + node.add(0x28).readPointer());
            console.log('  ' + describeRequest(node.add(0x28).readPointer()));
        } catch (e) {
            console.log('  node 读取失败: ' + e);
        }
    }
});

// ---------- Hook 4: blr x8 (protobuf 编码虚调用) ----------
// 记录被调用的真实虚函数地址与 autoBuffer 状态, 用于核对 blrX8Addr 与写入语义。
// 注意: 这是函数中段的一条指令, 只能用 onEnter。
// 加 onLeave 会让 Frida 改写栈上返回地址, 对非函数入口是破坏性的。
Interceptor.attach(base.add(OFF.blrX8), {
    onEnter: function (args) {
        var c = ctxByThread[this.threadId];
        var target = this.context.x8;
        var autoBuffer = this.context.x1;
        console.log('\n===== [4] blr x8 tid=' + this.threadId +
            ' taskId=' + (c ? c.taskId : '?') + ' x20=' + this.context.x20.toUInt32() + ' =====');
        console.log('  x8(target)=' + target + ' offset=' + target.sub(base));
        console.log('  x1(autoBuffer)=' + autoBuffer + ' raw: ' + dump(autoBuffer, 0x20));
        console.log('  x2(lenOut)=' + this.context.x2 + ' x3=' + this.context.x3 + ' x4=' + this.context.x4);
        console.log('  x0(request obj)=' + this.context.x0);
        console.log('  ' + describeRequest(this.context.x0));
    }
});

// ---------- Hook 5: Req2Buf epilogue ----------
Interceptor.attach(base.add(OFF.req2bufExit), {
    onEnter: function (args) {
        var c = ctxByThread[this.threadId];
        console.log('\n===== [5] Req2Buf EXIT tid=' + this.threadId +
            ' taskId=' + (c ? c.taskId : '?') +
            ' x25=' + this.context.x25.toUInt32() +
            ' 耗时=' + (c ? (Date.now() - c.t0) : '?') + 'ms =====');
        if (c && readable(c.session.add(0x60))) {
            console.log('  退出时任务表:\n      ' + walkMap(c.session.add(0x60)));
        }
        delete ctxByThread[this.threadId];
    }
});

// ---------- Hook 6: buf2resp (ACK) ----------
// 0x3e7e670 是函数中段(mov w28,#1), 紧跟在 autoBufferWrite 调用之后。
// 只读 sp+0x140 与 x0, 不做任何推断性写入。
Interceptor.attach(base.add(OFF.buf2Resp), {
    onEnter: function (args) {
        var respTaskId = 0;
        try {
            respTaskId = this.context.sp.add(0x140).readS32();
        } catch (e) {}
        var len = this.context.x0.toInt32();
        console.log('\n===== [6] buf2resp tid=' + this.threadId +
            ' taskId@sp+0x140=' + respTaskId + ' len(x0)=' + len +
            ' x20=' + this.context.x20 + ' =====');
    }
});

console.log('\n[OBS] 只读观察 hook 已全部安装 (StartTask / Req2Buf / map / blrX8 / exit / buf2resp)');
console.log('[OBS] 现在请在微信客户端里手动发送测试消息。');
