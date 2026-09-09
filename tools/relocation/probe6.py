import json, subprocess, sys, time
import frida

WPID = int(sys.argv[1])
sites = [int(s, 16) for s in json.load(open('/tmp/wxrelocate/safe_sites.json'))]
PROBE = r"""
const hookModule = Process.enumerateModules().find(m => m.path.endsWith("/Resources/wechat.dylib"));
const base = hookModule.base;
const counts = {};
const sites = %s;
for (const off of sites) {
  try {
    Interceptor.attach(base.add(off), {
      onEnter: function () {
        counts[off] = (counts[off] || 0) + 1;
        if (counts[off] <= 2) {
          let len = -1, head = '';
          try {
            len = this.context.x0.toInt32();
            if (len > 0 && len < 4194304) head = Array.from(new Uint8Array(this.context.x20.readByteArray(Math.min(16, len)))).map(x=>x.toString(16).padStart(2,'0')).join(' ');
          } catch (e) { head = 'err'; }
          send({ hit: off, n: counts[off], len: len, head: head });
        }
      }
    });
  } catch (e) { send({ attachFail: off, error: e.message }); }
}
send({ armed: sites.length });
""" % json.dumps(sites)

session = frida.attach(WPID)
script = session.create_script(PROBE)
def on_message(msg, data):
    if msg.get('type') == 'send':
        print('HIT:', json.dumps(msg['payload'], ensure_ascii=False), flush=True)
script.on('message', on_message)
script.load()
print('armed, waiting 8s...', flush=True)
time.sleep(8)
subprocess.run(['curl','-s','-m','20','-X','POST','http://127.0.0.1:58080/send_private_msg',
  '-H','Authorization: Bearer MuseBot','-H','Content-Type: application/json',
  '-d','{"user_id":"filehelper","message":[{"type":"text","data":{"text":"probe6 trigger"}}]}'],
  capture_output=True, text=True, timeout=30)
print('send triggered, collecting 60s...', flush=True)
time.sleep(60)
print('DONE', flush=True)
sys.exit(0)
