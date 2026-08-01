'use strict';

// 只读观察微信消息库 WAL 写入栈，用于定位本地消息入库的完整函数入口。
// fd 由外部 lsof 解析后注入；Hook 中只筛选并记录，不改寄存器或内存。

var QUIET_WINDOW_MS = 500;
var MAX_BURSTS = 40;

function globalExport(name) {
    if (typeof Module.findGlobalExportByName === 'function') {
        return Module.findGlobalExportByName(name);
    }
    try {
        return Module.getGlobalExportByName(name);
    } catch (error) {
        return null;
    }
}

function relativeFrame(address) {
    try {
        var owner = Process.findModuleByAddress(address);
        if (owner) return owner.name + '+' + address.sub(owner.base);
    } catch (error) {}
    return address.toString();
}

var pwriteAddress = globalExport('pwrite');
if (!pwriteAddress) {
    throw new Error('pwrite export unavailable');
}

var targetFds = {};
OBSERVED_MESSAGE_WAL_FDS.forEach(function (fd) {
    targetFds[String(fd)] = true;
    console.log('[MSG-WRITE] target fd=' + fd);
});

if (Object.keys(targetFds).length === 0) {
    throw new Error('no message database WAL descriptors found');
}

var lastBurstAt = 0;
var burstCount = 0;
Interceptor.attach(pwriteAddress, {
    onEnter: function (args) {
        var fd = args[0].toInt32();
        if (!targetFds[String(fd)] || burstCount >= MAX_BURSTS) return;

        var now = Date.now();
        if (now - lastBurstAt < QUIET_WINDOW_MS) return;
        lastBurstAt = now;
        burstCount++;

        var frames = Thread.backtrace(this.context, Backtracer.ACCURATE);
        console.log('\n===== [MESSAGE WAL BURST #' + burstCount + '] fd=' + fd +
            ' bytes=' + args[2] + ' offset=' + args[3] + ' =====');
        console.log('  backtrace:\n    ' + frames.map(relativeFrame).join('\n    '));
    }
});

console.log('[MSG-WRITE] 只读观察已安装，等待消息库写入；最多记录 ' + MAX_BURSTS + ' 个写入批次。');
