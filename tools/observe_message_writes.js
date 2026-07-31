'use strict';

// 只读观察微信消息库 WAL 写入栈，用于定位本地消息入库的完整函数入口。
// 加载时读取 fd 对应路径；Hook 中只筛选并记录，不改寄存器或内存。

var F_GETPATH = 50;
var MAX_FD = 512;
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

var fcntlAddress = globalExport('fcntl');
var pwriteAddress = globalExport('pwrite');
if (!fcntlAddress || !pwriteAddress) {
    throw new Error('fcntl/pwrite export unavailable');
}

var fcntl = new NativeFunction(fcntlAddress, 'int', ['int', 'int', 'pointer']);
var pathBuffer = Memory.alloc(1024);
var targetFds = {};

for (var fd = 0; fd < MAX_FD; fd++) {
    pathBuffer.writeByteArray(new Uint8Array(1024));
    if (fcntl(fd, F_GETPATH, pathBuffer) !== 0) continue;
    var path = pathBuffer.readUtf8String();
    if (/\/db_storage\/message\/message_[0-9]+\.db-wal$/.test(path)) {
        targetFds[String(fd)] = path;
        console.log('[MSG-WRITE] target fd=' + fd + ' path=' + path);
    }
}

if (Object.keys(targetFds).length === 0) {
    throw new Error('no message database WAL descriptors found');
}

var lastBurstAt = 0;
var burstCount = 0;
Interceptor.attach(pwriteAddress, {
    onEnter: function (args) {
        var fd = args[0].toInt32();
        var path = targetFds[String(fd)];
        if (!path || burstCount >= MAX_BURSTS) return;

        var now = Date.now();
        if (now - lastBurstAt < QUIET_WINDOW_MS) return;
        lastBurstAt = now;
        burstCount++;

        var frames = Thread.backtrace(this.context, Backtracer.ACCURATE);
        console.log('\n===== [MESSAGE WAL BURST #' + burstCount + '] fd=' + fd +
            ' bytes=' + args[2] + ' offset=' + args[3] + ' =====');
        console.log('  path=' + path);
        console.log('  backtrace:\n    ' + frames.map(relativeFrame).join('\n    '));
    }
});

console.log('[MSG-WRITE] 只读观察已安装，等待消息库写入；最多记录 ' + MAX_BURSTS + ' 个写入批次。');
