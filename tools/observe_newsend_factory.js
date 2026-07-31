'use strict';
// 只读观察 newsendmsg 的真实 request 工厂与构造函数。
// 仅在两个完整函数入口安装 Hook，不写内存、不改寄存器、不调用微信函数。

var OFF = {
    factory: 0x2a35900,
    constructor: 0x2a35ac8
};

var mods = Process.enumerateModules().filter(function (m) {
    return m.path.indexOf('/Contents/Resources/wechat.dylib') >= 0;
});
var mod = mods[0];
if (!mod || mod.size < 0x6000000) {
    throw new Error('未找到真正的 Resources/wechat.dylib');
}
var base = mod.base;

function readable(p) {
    try {
        if (!p || p.isNull()) return false;
        var range = Process.findRangeByAddress(p);
        return range !== null && range.protection.indexOf('r') !== -1;
    } catch (e) {
        return false;
    }
}

function readStdString(p) {
    try {
        if (!readable(p)) return '<unreadable>';
        var marker = p.add(23).readS8();
        if (marker >= 0) {
            return JSON.stringify(p.readUtf8String(marker));
        }
        var data = p.readPointer();
        var size = p.add(8).readU64().toNumber();
        if (!readable(data) || size > 1024 * 1024) return '<invalid-long-string>';
        return JSON.stringify(data.readUtf8String(size));
    } catch (e) {
        return '<string-error:' + e + '>';
    }
}

function dumpWords(p, len) {
    if (!readable(p)) return '<unreadable ' + p + '>';
    var out = [];
    for (var off = 0; off < len; off += 8) {
        try {
            out.push('+0x' + off.toString(16) + '=' + p.add(off).readU64());
        } catch (e) {
            out.push('+0x' + off.toString(16) + '=<read-error>');
            break;
        }
    }
    return out.join(' ');
}

function dumpReadablePointers(p, len) {
    if (!readable(p)) return '<unreadable ' + p + '>';
    var out = [];
    for (var off = 0; off < len; off += 8) {
        try {
            var candidate = p.add(off).readPointer();
            if (readable(candidate)) {
                out.push('+0x' + off.toString(16) + '->' + candidate + ' [' +
                    dumpWords(candidate, 0x30) + ']');
            }
        } catch (e) {}
    }
    return out.length ? out.join('\n    ') : '<no-readable-pointer-members>';
}

function relativeFrame(address) {
    try {
        var owner = Process.findModuleByAddress(address);
        if (owner) return owner.name + '+' + address.sub(owner.base);
    } catch (e) {}
    return address.toString();
}

var factoryCount = 0;
var firstFactoryAt = 0;
var previousFactoryAt = 0;
Interceptor.attach(base.add(OFF.factory), {
    onEnter: function () {
        factoryCount++;
        var now = Date.now();
        if (!firstFactoryAt) firstFactoryAt = now;
        this.factoryNumber = factoryCount;
        this.enteredAt = now;
        var x0 = this.context.x0;
        var x1 = this.context.x1;
        var x2 = this.context.x2;
        var x3 = this.context.x3;
        var x4 = this.context.x4;
        console.log('\n===== [NEWSEND FACTORY #' + factoryCount + '] tid=' + this.threadId +
            ' since-first=' + (now - firstFactoryAt) + 'ms' +
            ' since-previous=' + (previousFactoryAt ? now - previousFactoryAt : 0) + 'ms =====');
        previousFactoryAt = now;
        console.log('  x0(manager/interface)=' + x0 + ' ' + dumpWords(x0, 0x30));
        console.log('  x1(payload/source)=' + x1 + ' ' + dumpWords(x1, 0x60));
        console.log('  x1 readable pointer members:\n    ' + dumpReadablePointers(x1, 0x60));
        console.log('  x2(arg2)=' + x2 + ' raw=' + dumpWords(x2, 0x40));
        console.log('  x3(options)=' + x3 + ' raw=' + dumpWords(x3, 0x60));
        console.log('  x4(callback holder)=' + x4 + ' ' + dumpWords(x4, 0x40));
        var frames = Thread.backtrace(this.context, Backtracer.ACCURATE);
        console.log('  backtrace:\n    ' + frames.map(relativeFrame).join('\n    '));
    },
    onLeave: function (retval) {
        console.log('  [NEWSEND FACTORY #' + this.factoryNumber + ' RETURN] x0=' + retval +
            ' elapsed=' + (Date.now() - this.enteredAt) + 'ms');
    }
});

var constructorCount = 0;
Interceptor.attach(base.add(OFF.constructor), {
    onEnter: function () {
        constructorCount++;
        this.constructorNumber = constructorCount;
        this.request = this.context.x0;
        console.log('\n===== [NEWSEND CONSTRUCTOR #' + constructorCount + '] tid=' + this.threadId + ' =====');
        console.log('  request=' + this.context.x0 + ' source=' + this.context.x1);
        console.log('  source raw=' + dumpWords(this.context.x1, 0x38));
    },
    onLeave: function () {
        console.log('  [NEWSEND CONSTRUCTOR #' + this.constructorNumber + ' COMPLETE] request=' +
            this.request + ' raw=' + dumpWords(this.request, 0x120));
    }
});

console.log('[NEWSEND] wechat.dylib base=' + base + ' path=' + mod.path);
console.log('[NEWSEND] 已安装 2 个完整函数入口 Hook；0 写入、0 NativeFunction 调用。');
