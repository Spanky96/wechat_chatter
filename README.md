# WeChat 4.0 Message hook（Spanky 维护分支）

> 本项目 fork 自 [yincongcyincong/wechat_chatter](https://github.com/yincongcyincong/wechat_chatter)，
> 在其基础上针对微信 **4.1.11.53 (macOS)** 做了一系列修复与功能增强。

## 致谢原作

首先要感谢原项目作者 [yincongcyincong](https://github.com/yincongcyincong) 的开源分享。
逆向微信 macOS 客户端底层的收发消息能力是一项非常硬核的工作——原项目直接 Hook 了
微信三端统一的底层发消息链路（感兴趣的可以研究 google tencent/mars），
完整实现了消息接收、图片/文件/语音等消息类型的构造与发送，并提供了 OneBot 协议接入。
没有原作打下的基础，就没有这个分支的任何改进。原作的分享也来自 linux.do 社区的讨论：https://linux.do/

本代码库中的所有代码、示例、文档及相关内容（以下简称"本项目"）仅供学习、研究和技术交流之目的使用。使用本项目所产生的任何风险（包括但不限于数据丢失、系统崩溃、安全问题、法律风险等）均由使用者自行承担。

## 本分支的主要改动

### 新功能

- **小程序卡片发送**：新增 `mini_program` 消息段类型，通过 `BuildMiniProgramMsgProto` 构造 type=33 appmsg protobuf，
  支持 appid / username / pagepath / title 等字段，经 `--enable_mini_program_send` 独立开关控制（默认关闭，旧 Hook 存在崩溃风险）。
- **实验性文本发送**：实现真实的微信文本发送工厂 Hook，支持异步发送、取消与超时清理；
  由 `--enable_unsafe_send` 显式开启（默认关闭），开启后也仅放行 text / at 消息段，媒体类型继续禁用。
- **被动媒体下载监听**：新增 `--enable_media_download_hooks`，在不开启完整媒体上传/下载 Hook（可能降低微信稳定性）的前提下，
  仅监听媒体下载事件。

### 修复

- **私聊消息会话归属**：引入 `myWechatId` 正确识别自己的微信 ID，通过 `conversationUser` 区分"会话用户"与"实际发送者"，
  修复自己发出的私聊消息被归属到错误会话（UserID 错误）的问题。

### 稳定性与可运维性

- **进程附着机制重构**：改用 context 超时控制与更完善的错误处理，实现优雅的信号处理和资源清理，
  优化 Frida 脚本的加载/卸载流程，避免资源泄露。
- **发送/接收状态可观测**：`/send_status` 接口拆分展示接收 Hook 状态、文本发送生命周期诊断与小程序发送状态；
  接收 Hook 安装改为带重试并上报失败原因，便于排查"收不到消息"类问题。
- **版本配置精简**：只保留 `wechat_version/4_1_11_53_mac.json`，其他历史版本配置已移除
  （历史版本可回原仓库对应 release 查看）。

### 逆向分析工具

`tools/` 目录下新增一套只读观察脚本（不调用 NativeFunction、不修改内存），用于定位函数入口和分析消息管道：

- `observe_send.js` / `observe_send_safe.js` / `observe_newsend_factory.js`：观察发送工厂链路
- `observe_send_business_pipeline.js`：观察本地出站消息管道的完整函数入口
- `observe_message_storage_submit.js`：观察 MessageStorage 同步任务提交入口
- `observe_message_writes.js` + `run_observer.py`：通过外部 lsof 解析 fd 后注入观察消息 WAL 写入

另有配套的安全测试（`script_safety_test.go`、`http_send_safety_test.go`），
验证各实验开关关闭时对应的 Hook 不会启用、未支持的媒体消息类型会被正确拒绝。

## 版本支持

**本分支仅支持微信 4.1.11.53 (macOS)**，对应配置文件 `wechat_version/4_1_11_53_mac.json`。
其他微信版本请使用原仓库对应的 release。

## 使用方式

怎么使用，如果你的 mac 已经关闭了 SIP
```
frida -f /Applications/WeChat.app/Contents/MacOS/WeChat -l frida/text.js
triggerSendTextMessage(0x20000095, "wxid_xxxx", "hi")
```

没有关闭 SIP，查看文件 https://github.com/yincongcyincong/weixin-macos/blob/main/frida-gadget/readme.md
把每一步都执行完成，然后启动微信
```
frida -H 127.0.0.1:27042 -n Gadget -l ./frida/text.js
triggerSendTextMessage(0x20000095, "wxid_xxxx", "hi")
```

![image](https://github.com/user-attachments/assets/401de4b8-5d10-48d9-8dcf-eecc8ae8682a)

hook1 是触发函数，和用户回车行为一样，触发 startTask。

hook2 是对 Req2Buf 这个函数进行消息体注入，因为 hook1 触发的时候我其实没有给消息体，但是我注入的这个消息体，在 protobuf 过程中一直失败，全是指针，根本看不懂。

所以在 hook3 处我直接注入 protobuf 的内容，然后进行发送。

hook4 是在 Req2Buf，清除掉消息体的内容，因为后序在 OnTaskEnd 会回收内存，如果我这边消息体还在整个的指针上就会被清除，但是这个线程不认识这块内存，整个程序就会 crash。

## 图片消息
```
手动发送一张图片，为了让函数找到 X0 寄存器的数据。

mkdir -p "/Users/xxx/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/wxid_xxx/temp/xxx/2026-01/Img/"
cp /Users/xxx/Desktop/1.png "/Users/xxx/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/wxid_xxx/temp/xxx/2026-01/Img/xxx.jpg"

triggerUploadImg("wxid_xxx", "8dd4755e12e052fa5647a883e6bf0783", "/Users/xxx/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/wxid_xxx/temp/xxx/2026-01/Img/xxx.jpg")
triggerSendImgMessage(0x20000199, "wxid_xxx", "wxid_xxx")
```

## 支持 onebot 协议（http 接口）&& 如何接入 openclaw

见 [onebot/readme.md](./onebot/readme.md)

有兴趣的交流群：https://t.me/+yBnP4fxkoCIzZjRl
