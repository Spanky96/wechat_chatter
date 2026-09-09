#!/usr/bin/env python3
"""受限位点探针：只挂已验证代码簇内的 autoBufferWrite 后继点，运行 120 秒自动退出并汇总。"""
import json
import subprocess
import sys
import time

import frida

WECHAT_PID = int(sys.argv[1])
SITES = [int(s, 16) for s in json.load(open('/tmp/wxrelocate/safe_sites.json'))]

messages = []

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
        if (counts[off] === 1) {
          let len = -1, head = '';
          try {
            len = this.context.x0.toInt32();
            const p = this.context.x20;
            if (len > 0 && len < 4194304) {
              const b = p.readByteArray(Math.min(16, len));
              head = Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join(' ');
            }
          } catch (e) { head = 'err'; }
          send({ firstHit: off, len: len, head: head });
        }
      }
    });
  } catch (e) { send({ attachFail: off, error: e.message }); }
}
send({ armed: sites.length, base: base.toString() });
""" % json.dumps(SITES)


def main():
    session = frida.attach(WECHAT_PID)
    script = session.create_script(PROBE)

    def on_message(msg, data):
        if msg.get('type') == 'send':
            messages.append(msg['payload'])

    script.on('message', on_message)
    script.load()
    print('probe loaded', flush=True)
    time.sleep(5)
    # 触发一次发送（ACK 响应会经过响应解析路径）
    try:
        out = subprocess.run(
            ['curl', '-s', '-m', '20', '-X', 'POST', 'http://127.0.0.1:58080/send_private_msg',
             '-H', 'Authorization: Bearer MuseBot', '-H', 'Content-Type: application/json',
             '-d', '{"user_id":"filehelper","message":[{"type":"text","data":{"text":"probe5 ack-path trigger"}}]}'],
            capture_output=True, text=True, timeout=30)
        print('send result:', out.stdout[:200], flush=True)
    except Exception as e:
        print('send trigger failed:', e, flush=True)
    time.sleep(100)
    try:
        script.unload()
    finally:
        session.detach()
    print(json.dumps(messages, ensure_ascii=False, indent=1), flush=True)


if __name__ == '__main__':
    main()
