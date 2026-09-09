'use strict';

// 4.1.13 文本发送链只读观察器。
// 仅在完整函数入口读取寄存器、栈摘要和回溯；不写内存、不调用微信函数。
var OFF = {
    sendAsync: 0x21f3380,
    submitAsync: 0x21f3584,
    factory: 0x21f3f28,
    requestConstructor: 0x21f40f0,
};

var modules = Process.enumerateModules().filter(function (module) {
    return module.path.indexOf('/Contents/Resources/wechat.dylib') >= 0;
});
var wechat = modules.sort(function (a, b) { return b.size - a.size; })[0];
if (!wechat || wechat.size < 0x6000000) throw new Error('未找到 Resources/wechat.dylib');

function readable(pointer) {
    try {
        if (!pointer || pointer.isNull()) return false;
        var range = Process.findRangeByAddress(pointer);
        return range !== null && range.protection.indexOf('r') !== -1;
    } catch (error) { return false; }
}

function words(pointer, length) {
    if (!readable(pointer)) return '<unreadable ' + pointer + '>';
    var result = [];
    for (var offset = 0; offset < length; offset += 8) {
        try { result.push('+0x' + offset.toString(16) + '=' + pointer.add(offset).readPointer()); }
        catch (error) { result.push('+0x' + offset.toString(16) + '=<error>'); break; }
    }
    return result.join(' ');
}

function frame(address) {
    try {
        var owner = Process.findModuleByAddress(address);
        if (owner) return owner.name + '+' + address.sub(owner.base);
    } catch (error) {}
    return address.toString();
}

function backtrace(context) {
    return Thread.backtrace(context, Backtracer.ACCURATE).slice(0, 20).map(frame).join('\n    ');
}

var counts = {};
function hook(name, offset, inspect) {
    counts[name] = 0;
    Interceptor.attach(wechat.base.add(offset), {
        onEnter: function (args) {
            counts[name]++;
            if (counts[name] > 8) return;
            console.log('\n===== [' + name + ' #' + counts[name] + '] tid=' + this.threadId + ' =====');
            inspect.call(this, args);
            console.log('  backtrace:\n    ' + backtrace(this.context));
        },
        onLeave: function (retval) {
            if (counts[name] <= 8) console.log('  return=' + retval);
        }
    });
}

function registers(context) {
    return 'x0=' + context.x0 + ' x1=' + context.x1 + ' x2=' + context.x2 +
        ' x3=' + context.x3 + ' x4=' + context.x4 + ' x5=' + context.x5 +
        ' x6=' + context.x6 + ' x7=' + context.x7 + ' x8=' + context.x8;
}

hook('SEND_ASYNC', OFF.sendAsync, function () {
    console.log('  ' + registers(this.context));
    console.log('  x0 words=' + words(this.context.x0, 0x50));
    console.log('  x0+0x20 words=' + words(this.context.x0.add(0x20), 0x170));
});

hook('SUBMIT_ASYNC', OFF.submitAsync, function () {
    console.log('  ' + registers(this.context));
    console.log('  x0 words=' + words(this.context.x0, 0x40));
    console.log('  x1 words=' + words(this.context.x1, 0x170));
    console.log('  x2 words=' + words(this.context.x2, 0x40));
    console.log('  x3 words=' + words(this.context.x3, 0x40));
    console.log('  x8 words=' + words(this.context.x8, 0x40));
});

hook('FACTORY', OFF.factory, function () {
    console.log('  ' + registers(this.context));
    console.log('  x0 words=' + words(this.context.x0, 0x50));
    console.log('  x1 words=' + words(this.context.x1, 0x180));
    console.log('  x2 words=' + words(this.context.x2, 0x60));
    console.log('  x3 words=' + words(this.context.x3, 0x60));
    console.log('  x4 words=' + words(this.context.x4, 0x60));
});

hook('REQUEST_CONSTRUCTOR', OFF.requestConstructor, function () {
    console.log('  ' + registers(this.context));
    console.log('  destination words=' + words(this.context.x0, 0x170));
    console.log('  source words=' + words(this.context.x1, 0x60));
});

console.log('[4.1.13 SEND CHAIN] read-only hooks installed base=' + wechat.base + ' path=' + wechat.path);
