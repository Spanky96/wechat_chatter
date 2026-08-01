'use strict';

// Read-only observation of WeChat's local outbound-message pipeline.
// Hooks complete function entries only and never calls native functions or writes memory.

var OFF = {
    sendBusinessUpstream: 0x2b20858,
    startSendBusiness: 0x2c47ff8,
    startSendBusinessVariant: 0x2c4bff4,
    sendContextCtor: 0x2cacf60,
    sendContextCtorVariant: 0x2cad590,
    prepareShowSendMessage: 0x2bc8c0c,
    addSendMessageToDb: 0x2bcd2b4,
    storageSubmit: 0x33de9f0
};
var MAX_PER_HOOK = 24;

var modules = Process.enumerateModules().filter(function (module) {
    return module.path.indexOf('/Contents/Resources/wechat.dylib') >= 0;
});
var wechat = modules[0];
if (!wechat || wechat.size < 0x6000000) {
    throw new Error('real Resources/wechat.dylib was not found');
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

function libcxxString(pointer) {
    try {
        if (!pointer || pointer.isNull()) return '<null>';
        var marker = pointer.add(0x17).readS8();
        var data = marker < 0 ? pointer.readPointer() : pointer;
        var length = marker < 0 ? pointer.add(0x8).readU32() : marker;
        if (length < 0 || length > 512) return '<invalid-length:' + length + '>';
        return JSON.stringify(data.readUtf8String(length));
    } catch (error) {
        return '<read-error>';
    }
}

function backtrace(context) {
    return Thread.backtrace(context, Backtracer.ACCURATE)
        .slice(0, 18)
        .map(relativeFrame)
        .join('\n    ');
}

var counts = {};
function observe(name, offset, inspect) {
    counts[name] = 0;
    Interceptor.attach(wechat.base.add(offset), {
        onEnter: function (args) {
            if (counts[name] >= MAX_PER_HOOK) return;
            counts[name]++;
            console.log('\n===== [' + name + ' #' + counts[name] + '] at=' + Date.now() + ' =====');
            inspect.call(this, args);
            console.log('  backtrace:\n    ' + backtrace(this.context));
        }
    });
}

observe('SEND-BUSINESS-UPSTREAM', OFF.sendBusinessUpstream, function (args) {
    console.log('  x0=' + args[0] + ' x1=' + args[1] + ' x2=' + args[2] +
        ' x3=' + args[3] + ' x4=' + args[4] + ' x5=' + args[5] +
        ' x6=' + args[6] + ' x7=' + args[7]);
    console.log('  x1-string=' + libcxxString(args[1]));
    console.log('  x3-words=' + pointerWords(args[3], 0x100));
});

observe('START-SEND-BUSINESS', OFF.startSendBusiness, function (args) {
    console.log('  x0=' + args[0] + ' x1=' + args[1] + ' x2=' + args[2] +
        ' x3=' + args[3] + ' x4=' + args[4] + ' x5=' + args[5] +
        ' x6=' + args[6] + ' x7=' + args[7] + ' x8=' + this.context.x8);
    console.log('  x1-string=' + libcxxString(args[1]));
    console.log('  x0-words=' + pointerWords(args[0], 0x60));
    console.log('  x2-words=' + pointerWords(args[2], 0x40));
});

observe('START-SEND-BUSINESS-VARIANT', OFF.startSendBusinessVariant, function (args) {
    console.log('  x0=' + args[0] + ' x1=' + args[1] + ' x2=' + args[2] +
        ' x3=' + args[3] + ' x4=' + args[4] + ' x5=' + args[5] +
        ' x6=' + args[6] + ' x7=' + args[7] + ' x8=' + this.context.x8);
    console.log('  session=' + libcxxString(args[1]));
    console.log('  x0-words=' + pointerWords(args[0], 0x80));
    console.log('  x3-words=' + pointerWords(args[3], 0x100));
    console.log('  x4-words=' + pointerWords(args[4], 0x80));
});

function inspectSendContextCtor(args, context) {
    console.log('  dst=' + args[0] + ' arg1=' + args[1] + ' arg2=' + args[2] +
        ' session=' + libcxxString(args[3]) + ' arg4=' + args[4] +
        ' arg5=' + args[5] + ' arg6=' + args[6] + ' arg7=' + args[7]);
    console.log('  arg1-words=' + pointerWords(args[1], 0x30));
    console.log('  arg2-words=' + pointerWords(args[2], 0x80));
    console.log('  arg4-words=' + pointerWords(args[4], 0x40));
    console.log('  stack-words=' + pointerWords(context.sp, 0x40));
}

observe('SEND-CONTEXT-CTOR', OFF.sendContextCtor, function (args) {
    inspectSendContextCtor(args, this.context);
});

observe('SEND-CONTEXT-CTOR-VARIANT', OFF.sendContextCtorVariant, function (args) {
    inspectSendContextCtor(args, this.context);
});

observe('PREPARE-SHOW-SEND', OFF.prepareShowSendMessage, function (args) {
    console.log('  storage=' + args[0] + ' arg1=' + args[1] + ' arg2=' + args[2] +
        ' arg3=' + args[3] + ' session=' + libcxxString(args[4]));
    console.log('  arg1-words=' + pointerWords(args[1], 0x40));
    console.log('  arg2-words=' + pointerWords(args[2], 0x40));
});

observe('ADD-SEND-MESSAGE-DB', OFF.addSendMessageToDb, function (args) {
    console.log('  storage=' + args[0] + ' messages=' + args[1] +
        ' session=' + libcxxString(args[2]) + ' flag3=' + args[3] +
        ' flag4=' + args[4] + ' arg5=' + args[5] + ' arg6=' + args[6] +
        ' arg7=' + args[7]);
    console.log('  messages-words=' + pointerWords(args[1], 0x30));
    console.log('  arg5-string=' + libcxxString(args[5]));
});

observe('STORAGE-SUBMIT-BASELINE', OFF.storageSubmit, function (args) {
    var holder = args[1];
    var callable = ptr(0);
    try {
        callable = holder.add(0x18).readPointer();
    } catch (error) {}
    console.log('  storage=' + args[0] + ' holder=' + holder + ' callable=' + callable);
    console.log('  callable-words=' + pointerWords(callable, 0x30));
});

console.log('[SEND-PIPELINE] read-only business pipeline observer installed');
