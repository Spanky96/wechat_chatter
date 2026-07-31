#!/usr/bin/env python3
"""稳健的 Frida 观察驱动。

直接用 frida Python API attach + load, 不依赖 CLI REPL / stdin。
console.log 通过一个 shim 转发成 send(), 由 on_message 写入日志文件,
避免 CLI 在 stdin EOF 时卸载脚本导致 hook 静默失效。

用法: python3 run_observer.py <wechat_pid> <script.js> <logfile>
"""
import sys
import threading

import frida

PID = int(sys.argv[1])
SCRIPT_PATH = sys.argv[2]
LOG_PATH = sys.argv[3]

# 把 console.log 同时转成 send(), 保证 Python 端可靠收到每一行
SHIM = (
    "console.log=(function(o){return function(){"
    "var s=Array.prototype.slice.call(arguments).join(' ');"
    "try{send(s)}catch(e){}"
    "return o.apply(console,arguments)"
    "}})(console.log);\n"
)

out = open(LOG_PATH, "a", buffering=1)


def log(line):
    out.write(str(line) + "\n")
    out.flush()


def on_message(msg, data):
    mtype = msg.get("type")
    if mtype == "send":
        log(msg.get("payload"))
    elif mtype == "error":
        log("SCRIPT-ERR: " + str(msg.get("stack") or msg.get("description") or msg))
    else:
        log("MSG: " + str(msg))


def on_detached(reason, crash):
    log("SESSION-DETACHED reason=" + str(reason) + " crash=" + str(crash))


def main():
    device = frida.get_local_device()
    session = device.attach(PID)
    session.on("detached", on_detached)
    with open(SCRIPT_PATH) as f:
        src = SHIM + f.read()
    script = session.create_script(src)
    script.on("message", on_message)
    script.load()
    log("[DRIVER] attached pid=%d, script loaded, waiting for WeChat traffic..." % PID)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        log("[DRIVER] stop requested, unloading read-only observer...")
    finally:
        try:
            script.unload()
        except frida.InvalidOperationError:
            pass
        try:
            session.detach()
        except frida.InvalidOperationError:
            pass
        out.close()


if __name__ == "__main__":
    main()
