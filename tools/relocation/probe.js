const mod = Process.getModuleByName("wechat.dylib");
send({ base: mod.base.toString(), size: mod.size, path: mod.path });
const targets = {
  'buf2Resp+0(hook点)': 0x43070a4,
  'SendAsync': 0x21f3380,
  'autoBufferWrite': 0x43084c0,
  '旧4.1.11的buf2Resp位置': 0x3e7e670
};
for (const [name, off] of Object.entries(targets)) {
  const addr = mod.base.add(off);
  try {
    const bytes = addr.readByteArray(16);
    send({ name, offset: '0x' + off.toString(16), addr: addr.toString(), hexdump: hexdump(addr, { length: 16, header: false, ansi: false }) });
  } catch (e) {
    send({ name, offset: '0x' + off.toString(16), error: e.message });
  }
}
