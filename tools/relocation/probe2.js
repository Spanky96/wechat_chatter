const hookModule = Process.enumerateModules().find(m => m.path.endsWith("/Resources/wechat.dylib"));
send({ base: hookModule.base.toString(), size: hookModule.size });
for (const [name, off] of Object.entries({
  'buf2Resp(hook点)': 0x43070a4,
  '函数头候选0x4307040': 0x4307040,
  'SendAsync': 0x21f3380,
  'autoBufferWrite': 0x43084c0
})) {
  send({ name, off: '0x'+off.toString(16), dump: hexdump(hookModule.base.add(off), { length: 16, header: false, ansi: false }) });
}
