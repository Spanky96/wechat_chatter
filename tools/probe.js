'use strict';
// 诊断探针: 确认 Interceptor.attach 是否真的改写了目标函数,
// 以及 MMStartTask / Req2Buf 到底有没有被微信调用。
// 只挂两个函数入口, 只读字节 + 计数, 不写任何业务内存。

var mod = Process.enumerateModules().filter(function (m) {
    return m.path.indexOf('wechat.dylib') >= 0;
})[0];
if (!mod) throw new Error('wechat.dylib 未加载');
var base = mod.base;
send('base=' + base);

function bytes(p, n) {
    var out = [];
    for (var i = 0; i < n; i++) {
        try { out.push(p.add(i).readU8().toString(16).padStart(2, '0')); }
        catch (e) { out.push('??'); }
    }
    return out.join(' ');
}

var SITES = { startTask: 0x5120fd8, req2bufEnter: 0x3e58e44 };

for (var k in SITES) {
    send('BEFORE ' + k + ' @' + base.add(SITES[k]) + ' : ' + bytes(base.add(SITES[k]), 16));
}

var fired = { startTask: 0, req2bufEnter: 0 };
Interceptor.attach(base.add(SITES.startTask), {
    onEnter: function () {
        fired.startTask++;
        send('FIRED startTask #' + fired.startTask + ' tid=' + this.threadId);
    }
});
Interceptor.attach(base.add(SITES.req2bufEnter), {
    onEnter: function () {
        fired.req2bufEnter++;
        send('FIRED req2buf #' + fired.req2bufEnter + ' taskId=' + this.context.x1.toUInt32() + ' tid=' + this.threadId);
    }
});

for (var k2 in SITES) {
    send('AFTER  ' + k2 + ' @' + base.add(SITES[k2]) + ' : ' + bytes(base.add(SITES[k2]), 16));
}

send('PROBE-READY: 两个入口 hook 已装。若 BEFORE/AFTER 字节不同=已成功改写; 之后请在微信里发一条消息看是否 FIRED。');
