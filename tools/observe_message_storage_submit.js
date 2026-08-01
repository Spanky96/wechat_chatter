'use strict';

// 只读观察 MessageStorage 的同步任务提交入口。
// 仅读取参数与调用栈，不调用 NativeFunction，不写寄存器或目标内存。

var OFF = {
    storageSubmit: 0x33de9f0
};
var MAX_CAPTURES = 300;

var modules = Process.enumerateModules().filter(function (module) {
    return module.path.indexOf('/Contents/Resources/wechat.dylib') >= 0;
});
var wechat = modules[0];
if (!wechat || wechat.size < 0x6000000) {
    throw new Error('未找到真正的 Resources/wechat.dylib');
}

function readable(pointer) {
    try {
        if (!pointer || pointer.isNull()) return false;
        var range = Process.findRangeByAddress(pointer);
        return range !== null && range.protection.indexOf('r') !== -1;
    } catch (error) {
        return false;
    }
}

function relativeFrame(address) {
    try {
        var owner = Process.findModuleByAddress(address);
        if (owner) return owner.name + '+' + address.sub(owner.base);
    } catch (error) {}
    return address.toString();
}

function pointerWords(pointer, length) {
    if (!readable(pointer)) return '<unreadable>';
    var words = [];
    for (var offset = 0; offset < length; offset += Process.pointerSize) {
        try {
            words.push('+0x' + offset.toString(16) + '=' + pointer.add(offset).readPointer());
        } catch (error) {
            words.push('+0x' + offset.toString(16) + '=<read-error>');
            break;
        }
    }
    return words.join(' ');
}

var captureCount = 0;
Interceptor.attach(wechat.base.add(OFF.storageSubmit), {
    onEnter: function (args) {
        if (captureCount >= MAX_CAPTURES) return;
        captureCount++;

        var holder = args[1];
        var callable = ptr(0);
        var vtable = ptr(0);
        try {
            callable = holder.add(0x18).readPointer();
            if (readable(callable)) vtable = callable.readPointer();
        } catch (error) {}

        var frames = Thread.backtrace(this.context, Backtracer.ACCURATE);
        console.log('\n===== [MESSAGE STORAGE SUBMIT #' + captureCount + '] at=' + Date.now() + ' =====');
        console.log('  storage=' + args[0] + ' holder=' + holder +
            ' callable=' + callable + ' vtable=' + relativeFrame(vtable));
        console.log('  callable words=' + pointerWords(callable, 0x30));
        console.log('  backtrace:\n    ' + frames.map(relativeFrame).join('\n    '));
    }
});

console.log('[MSG-STORAGE] MessageStorage 提交入口只读观察已安装；最多记录 ' + MAX_CAPTURES + ' 次。');
