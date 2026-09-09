const hookModule = Process.enumerateModules().find(m => m.path.endsWith("/Resources/wechat.dylib"));
const base = hookModule.base;
let hits = 0;
Interceptor.attach(base.add(0x43070a4), {
  onEnter: function () {
    hits += 1;
    if (hits <= 5) {
      const len = this.context.x0.toInt32();
      const dataPtr = this.context.x20;
      let head = '';
      try { head = hexdump(dataPtr, { length: 16, header: false, ansi: false }).split('\n')[1]; } catch (e) { head = 'unreadable: ' + e.message; }
      send({ hit: hits, len, head });
    }
  }
});
send({ armed: true, base: base.toString() });
setInterval(() => send({ alive: true, hits }), 30000);
