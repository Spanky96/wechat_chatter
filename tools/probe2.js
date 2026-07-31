'use strict';
// 诊断2: 枚举所有含 wechat 的模块, 打印 base/size, 确认我 hook 的到底是哪个模块,
// 以及目标偏移是否真的落在该模块范围内。

var all = Process.enumerateModules();
send('模块总数=' + all.length);
all.filter(function (m) {
    return /wechat/i.test(m.path);
}).forEach(function (m) {
    send('MOD ' + m.name + ' base=' + m.base + ' size=' + m.size +
        ' (0x' + m.size.toString(16) + ') path=' + m.path);
    // 读模块头 4 字节 (mach-o magic 应为 cf fa ed fe)
    var magic = '';
    try {
        magic = m.base.readU32().toString(16);
    } catch (e) { magic = 'read-fail'; }
    send('    base+0 magic=0x' + magic + '  0x5120fd8在模块内=' +
        (m.size > 0x5120fd8) + '  0x3e58e44在模块内=' + (m.size > 0x3e58e44));
});

// 我脚本里 filter 命中的那个
var picked = all.filter(function (m) { return m.path.indexOf('wechat.dylib') >= 0; })[0];
if (picked) {
    send('PICKED=' + picked.name + ' base=' + picked.base + ' size=0x' + picked.size.toString(16));
    send('PICKED base+0x5120fd8 前16字节: ' + (function () {
        var o = [];
        for (var i = 0; i < 16; i++) { try { o.push(picked.base.add(0x5120fd8 + i).readU8().toString(16).padStart(2, '0')); } catch (e) { o.push('??'); } }
        return o.join(' ');
    })());
}
send('PROBE2-DONE');
