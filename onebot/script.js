var modules = Process.enumerateModules();
var executableModule = modules.find(function(m) {
    return m.path === "/Applications/WeChat.app/Contents/MacOS/WeChat";
});
var hookModule = modules.find(function(m) {
    return m.path.endsWith("/WeChat.app/Contents/Resources/wechat.dylib");
});
var baseAddr = null;

if (hookModule) {
    baseAddr = hookModule.base;
    console.log("[+] wechat.dylib base: " + baseAddr + " size=" + hookModule.size);
    initAddresses();
} else {
    if (!executableModule) {
        throw new Error("[-] Cannot find WeChat executable module");
    }

    // 旧版本兜底：在主模块后的地址空间扫描 wechat.dylib 特征串。
    var searchEnd = executableModule.base.add(1000 * 1024 * 1024);
    var matchAddress = null;
    var ranges = Process.enumerateRanges("r--").filter(function(r) {
        var rangeEnd = r.base.add(r.size);
        return r.base.compare(searchEnd) < 0 && rangeEnd.compare(executableModule.base) > 0;
    });
    var pending = ranges.length;
    if (pending === 0) {
        throw new Error("[-] No readable ranges found near WeChat module");
    }

    ranges.forEach(function(r) {
        Memory.scan(r.base, r.size, "72 65 71 32 62 75 66", {
            onMatch: function(address) {
                if (matchAddress === null) matchAddress = address;
            },
            onError: function() {},
            onComplete: function() {
                pending--;
                if (pending !== 0) return;
                if (matchAddress === null) {
                    throw new Error("[-] Cannot locate wechat.dylib base");
                }
                baseAddr = Process.findRangeByAddress(matchAddress).base;
                console.log("[fallback] wechat.dylib base from scan: " + baseAddr);
                initAddresses();
            }
        });
    });
}

// [native-send-hunt] hook 总提交口（8个编排器的公共下游），UI 发送必经，栈回溯暴露原生路径
var submitBtState = { n: 0 };
function setupSubmitBacktrace() {
    Interceptor.attach(baseAddr.add(0x62cf4e4), {
        onEnter: function () {
            if (submitBtState.n >= 40) return;
            submitBtState.n += 1;
            var frames = Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0, 14);
            var parts = [];
            for (var i = 0; i < frames.length; i++) {
                var off = frames[i].sub(baseAddr);
                var n = off.toInt32 ? off.toInt32() : parseInt(off.toString(), 16);
                parts.push('0x' + (n < 0 ? (n >>> 0).toString(16) : n.toString(16)));
            }
            console.log('[submit-bt ' + submitBtState.n + ' t=' + Date.now() + '] x0=' + this.context.x0 + ' x1=' + this.context.x1 + ' stack=' + parts.join(' <- '));
        }
    });
    console.log('[submit-bt] 总提交口回溯已挂载');
}

// [classic-path-hunt] 双胞胎序列化器入口回溯：发送时暴露新版 req2buf 包装器
var twinBtState = { n: 0 };
function setupTwinBacktrace() {
    [0x429f838, 0x429fb58].forEach(function (off) {
        try {
            Interceptor.attach(baseAddr.add(off), {
                onEnter: function () {
                    if (twinBtState.n >= 8) return;
                    twinBtState.n += 1;
                    var frames = Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0, 10);
                    var parts = [];
                    for (var i = 0; i < frames.length; i++) {
                        var n = frames[i].sub(baseAddr).toInt32();
                        parts.push('0x' + (n < 0 ? (n >>> 0).toString(16) : n.toString(16)));
                    }
                    console.log('[twin-bt ' + twinBtState.n + ' fn=0x' + off.toString(16) + '] x0=' + this.context.x0 + ' x1=' + this.context.x1 + ' x2=' + this.context.x2 + ' stack=' + parts.join(' <- '));
                }
            });
        } catch (e) { console.warn('[twin-bt] attach失败 0x' + off.toString(16) + ': ' + e.message); }
    });
    console.log('[twin-bt] 双胞胎回溯已挂载');
}

// [classic-send] 捕获真实任务的 x1 模板（0x1A0 字节）用于 4.1.13 布局 diff
var realX1State = { n: 0 };
function setupRealX1Capture() {
    Interceptor.attach(sendFuncAddr, {
        onEnter: function () {
            if (realX1State.n >= 2) return;
            realX1State.n += 1;
            var x1 = this.context.x1;
            try {
                var bytes = new Uint8Array(x1.readByteArray(0x300));
                var parts = [];
                for (var i = 0; i < bytes.length; i++) parts.push(bytes[i].toString(16).padStart(2, '0'));
                lastRealX1Bytes = parts.join('');
            lastRealX1Addr = x1;
            console.log('[real-x1 ' + realX1State.n + '] x1addr=' + x1 + ' x0=' + this.context.x0 + ' hex=' + parts.join(''));
            } catch (e) {
                console.warn('[real-x1] 读取失败: ' + e.message);
            }
        }
    });
    console.log('[real-x1] 真实X1采样已挂载 @sendFunc');
}


// [classic-send] 采样健康任务的 x1 模板（排除我们自己的 newsendmsg 失败重试任务）
var realX1State = { n: 0 };
function setupRealX1Capture() {
    Interceptor.attach(sendFuncAddr, {
        onEnter: function () {
            // X0 持续刷新：原 +0x10 处的独立 hook 在部分会话不触发（重定位块交互问题），
            // 入口 hook 实测每次任务都触发，在此一并捕获 manager。
            if (!triggeringStartTask) {
                try {
                    var cx0 = this.context.x0;
                    if (isReadablePointer(cx0) && (!triggerX0 || !cx0.equals(triggerX0))) {
                        triggerX0 = cx0;
                        console.log('[+] 捕获到有效 StartTask 调用，X0：' + triggerX0);
                    }
                } catch (e0) { /* manager 捕获失败不影响采样 */ }
            }
            if (realX1State.n >= 3 && lastRealX1Bytes) {
                // 已有模板：继续静默刷新（保持新鲜），仅不再打印日志
            }
            var x1 = this.context.x1;
            try {
                // 模板只用 newsync：longlink 同步任务微信持续重发、外部指针长期有效；
                // reportkv 等一次性任务完成后外部对象被释放，克隆会 access violation（0x4001...实测）
                var cgiPtr = x1.add(0x18).readPointer();
                var cgi = cgiPtr.readCString();
                if (!cgi || cgi.indexOf('/newsync') < 0) return;
                var willLog = realX1State.n < 3;
                realX1State.n += 1;
                var bytes = new Uint8Array(x1.readByteArray(0x300));
                var parts = [];
                for (var i = 0; i < bytes.length; i++) parts.push(bytes[i].toString(16).padStart(2, '0'));
                lastRealX1Bytes = parts.join('');
                lastRealX1Addr = x1;
                if (willLog) console.log('[real-x1 ' + realX1State.n + '] cgi=' + cgi + ' x1addr=' + x1 + ' hex=' + parts.join(''));
                if (realX1State.n === 1) {
                    // 指针图：结构体内指向外部的指针 + 目标首个 qword（vtable 候选），供定位消息对象/encode 函数
                    try {
                        var ptrMap = [];
                        for (var poff = 0; poff + 8 <= 0x300; poff += 8) {
                            var pv = x1.add(poff).readPointer();
                            if (pv.isNull() || pv.compare(x1) >= 0 && pv.compare(x1.add(0x300)) < 0) continue;
                            var vt = ptr(0);
                            try { vt = pv.readPointer(); } catch (e2) { continue; }
                            if (vt.isNull() || vt.compare(baseAddr) < 0 || vt.compare(baseAddr.add(0xa000000)) >= 0) continue;
                            ptrMap.push('+' + poff.toString(16) + '->' + pv + ' vt=' + vt.sub(baseAddr));
                        }
                        console.log('[real-x1-ptrmap] ' + ptrMap.join(' | '));
                    } catch (e3) { /* 指针图失败不影响采样 */ }
                }
            } catch (e) { /* 跳过不可读任务 */ }
        }
    });
    console.log('[real-x1] 健康X1采样已挂载 @sendFunc');
}

function initAddresses() {
    // 文本消息全局变量 (new_text.js approach)
    blrX8Addr = baseAddr.add({{.blrX8Addr}});
    autoBufferWriteFunc = baseAddr.add({{.autoBufferWriteFunc}});

    // 双方公共使用的地址
    req2bufEnterAddr = baseAddr.add({{.req2bufEnterAddr}});
    req2bufExitAddr = baseAddr.add({{.req2bufExitAddr}});
    sendFuncAddr = baseAddr.add({{.sendFuncAddr}});
    sendDirectFuncAddr = {{if .sendDirectFuncAddr}}baseAddr.add({{.sendDirectFuncAddr}}){{else}}ptr(0){{end}};
    buf2RespAddr = baseAddr.add({{.buf2RespAddr}});
    receiveResponseAddr = {{if .receiveResponseAddr}}baseAddr.add({{.receiveResponseAddr}}){{else}}buf2RespAddr{{end}};
    receiveResponseMode = {{if .receiveResponseMode}}"{{.receiveResponseMode}}"{{else}}"legacy"{{end}};

    realTextSendAsyncAddr = {{if .realTextSendAsyncAddr}}baseAddr.add({{.realTextSendAsyncAddr}}){{else}}ptr(0){{end}};
    realTextSubmitAsyncAddr = {{if .realTextSubmitAsyncAddr}}baseAddr.add({{.realTextSubmitAsyncAddr}}){{else}}ptr(0){{end}};
    realTextManagerProviderAddr = {{if .realTextManagerProviderAddr}}baseAddr.add({{.realTextManagerProviderAddr}}){{else}}ptr(0){{end}};
    realTextSendFactoryAddr = {{if .realTextSendFactoryAddr}}baseAddr.add({{.realTextSendFactoryAddr}}){{else}}ptr(0){{end}};
    realTextRequestCtorAddr = {{if .realTextRequestCtorAddr}}baseAddr.add({{.realTextRequestCtorAddr}}){{else}}ptr(0){{end}};
    realTextEncoderAddr = {{if .realTextEncoderAddr}}baseAddr.add({{.realTextEncoderAddr}}){{else}}ptr(0){{end}};
    realTextResponseAddr = {{if .realTextResponseAddr}}baseAddr.add({{.realTextResponseAddr}}){{else}}ptr(0){{end}};
    realTextReq2BufAddr = {{if .realTextReq2BufAddr}}baseAddr.add({{.realTextReq2BufAddr}}){{else}}ptr(0){{end}};
    realTextAutoBufferDataAddr = {{if .realTextAutoBufferDataAddr}}baseAddr.add({{.realTextAutoBufferDataAddr}}){{else}}ptr(0){{end}};
    realTextAutoBufferLengthAddr = {{if .realTextAutoBufferLengthAddr}}baseAddr.add({{.realTextAutoBufferLengthAddr}}){{else}}ptr(0){{end}};
    realTextPayloadCtorAddr = {{if .realTextPayloadCtorAddr}}baseAddr.add({{.realTextPayloadCtorAddr}}){{else}}ptr(0){{end}};
    realTextParseFromArrayAddr = {{if .realTextParseFromArrayAddr}}baseAddr.add({{.realTextParseFromArrayAddr}}){{else}}ptr(0){{end}};
    realTextPayloadDtorAddr = {{if .realTextPayloadDtorAddr}}baseAddr.add({{.realTextPayloadDtorAddr}}){{else}}ptr(0){{end}};
    realTextResultDtorAddr = {{if .realTextResultDtorAddr}}baseAddr.add({{.realTextResultDtorAddr}}){{else}}ptr(0){{end}};
    realTextFutureDtorAddr = {{if .realTextFutureDtorAddr}}baseAddr.add({{.realTextFutureDtorAddr}}){{else}}ptr(0){{end}};

    uploadImageAddr = baseAddr.add({{.uploadImageAddr}});
    cndOnCompleteAddr = baseAddr.add({{.cndOnCompleteAddr}});

    uploadGetCallbackWrapperAddr = baseAddr.add({{.uploadGetCallbackWrapperAddr}});
    uploadGetCallbackWrapperFuncAddr = baseAddr.add({{.uploadGetCallbackWrapperFuncAddr}});
    uploadOnCompleteAddr = baseAddr.add({{.uploadOnCompleteAddr}});
    uploadOnCompleteFuncAddr = baseAddr.add({{.uploadOnCompleteFuncAddr}});
    downloadImagAddr = baseAddr.add({{.downloadImagAddr}});
    startDownloadMedia = baseAddr.add({{.startDownloadMedia}});
    downloadFileAddr = baseAddr.add({{.downloadFileAddr}});
    downloadVideoAddr = baseAddr.add({{.downloadVideoAddr}});

	sendMessageCallbackFunc = baseAddr.add(0x0);
	imgMessageCallbackFunc = baseAddr.add(0x0);
	videoMessageCallbackFunc = baseAddr.add(0x0);
    replyMessageCallbackFunc = baseAddr.add(0x0);
    voiceMessageCallbackFunc = baseAddr.add(0x0);

    scheduleHookSetup("消息接收", setupReceiverWithRetry);
    {{if .EnableUnsafeSend}}

    {{end}}
    {{if .EnableUnsafeSend}}

    {{end}}
    {{if .EnableUnsafeSend}}
    scheduleHookSetup("真实工厂文本发送", setupRealTextSend);
    scheduleHookSetup("经典文本发送", setupClassicTextSend);
    scheduleHookSetup("健康X1采样", setupRealX1Capture);

    {{else}}
    console.log("[receive-only] 后台文本发送已禁用，仅启用消息接收");
    {{end}}
    {{if .EnableMiniProgramSend}}
    scheduleHookSetup("小程序卡片发送", setupMiniProgramSend);
    {{else}}
    console.log("[safe-mode] 小程序卡片发送 Hook 已禁用");
    {{end}}
}

function runHookSetup(name, setup) {
    try {
        setup();
    } catch (error) {
        console.log("[hook-disabled] " + name + " 初始化失败: " + error + " stack=" + (error.stack || ""));
    }
}

function scheduleHookSetup(name, setup) {
    setImmediate(function() {
        runHookSetup(name, setup);
    });
}

// -------------------------基础函数分区-------------------------
function hexToByteArray(hexStr) {
    var bytes = [];
    for (var i = 0; i < hexStr.length; i += 2) {
        bytes.push(parseInt(hexStr.substr(i, 2), 16));
    }
    return bytes;
}

function patchString(addr, plainStr) {
    const bytes = [];
    for (let i = 0; i < plainStr.length; i++) {
        bytes.push(plainStr.charCodeAt(i));
    }

    addr.writeByteArray(bytes);
    addr.add(bytes.length).writeU8(0);
}

function generateAESKey() {
    const chars = 'abcdef0123456789';
    let key = '';
    for (let i = 0; i < 32; i++) {
        key += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return key;
}

const MAX_FRIDA_MESSAGE_BYTES = 4 * 1024 * 1024;

function isReadablePointer(addr) {
    try {
        if (!addr || addr.isNull()) {
            return false;
        }
        const range = Process.findRangeByAddress(addr);
        return range !== null && range.protection.indexOf('r') !== -1;
    } catch (e) {
        return false;
    }
}

function isWritablePointer(addr, size) {
    try {
        if (!addr || addr.isNull()) return false;
        const range = Process.findRangeByAddress(addr);
        if (!range || range.protection.indexOf('w') === -1) return false;
        return addr.add(size || 1).compare(range.base.add(range.size)) <= 0;
    } catch (e) {
        return false;
    }
}

function readPointerIfReadable(addr) {
    try {
        if (!isReadablePointer(addr)) {
            return ptr(0);
        }
        const value = addr.readPointer();
        if (!isReadablePointer(value)) {
            return ptr(0);
        }
        return value;
    } catch (e) {
        return ptr(0);
    }
}

function readUtf8StringIfReadable(addr) {
    try {
        if (!isReadablePointer(addr)) {
            return "";
        }
        return addr.readUtf8String();
    } catch (e) {
        return "";
    }
}

function readByteArrayIfReadable(addr, len) {
    try {
        if (len <= 0 || !isReadablePointer(addr)) {
            return null;
        }
        return addr.readByteArray(len);
    } catch (e) {
        return null;
    }
}

function sendDownloadChunks(dataPtr, dataLen, fileId, cdnUrl) {
    if (!cdnUrl || dataLen <= 0) {
        return;
    }

	if (dataLen > 0 && dataLen <= 10 * 1024 * 1024) {
		var buffer = dataPtr.readByteArray(dataLen);
		var uint8Array = new Uint8Array(buffer);

		send({
			type: "download",
			media: Array.from(uint8Array),
			file_id: fileId,
			cdn_url: cdnUrl,
		})
	}
}

function fillUploadX1AndStart(idAddr, pathAddr, x1Buffer, receiver, md5, filePath, payloadHex) {
    if (uploadGlobalX0.equals(ptr(0))) {
        console.error("[!] uploadGlobalX0 尚未初始化，请等待 hook 捕获");
        return "fail";
    }

    const payload = hexToByteArray(payloadHex);
    patchString(idAddr, receiver + "_" + String(Math.floor(Date.now() / 1000)) + "_" + Math.floor(Math.random() * 1001) + "_1");
    patchString(md5Addr, md5);
    patchString(uploadAesKeyAddr, generateAESKey());
    patchString(pathAddr, filePath);

    x1Buffer.writeByteArray(payload);
    x1Buffer.writePointer(uploadFunc1Addr);
    x1Buffer.add(0x08).writePointer(uploadFunc2Addr);
    x1Buffer.add(0x48).writePointer(idAddr);
    x1Buffer.add(0x68).writeUtf8String(receiver);
    x1Buffer.add(0xa8).writePointer(md5Addr);
    x1Buffer.add(0xe8).writePointer(pathAddr);
    x1Buffer.add(0x118).writePointer(pathAddr);
    x1Buffer.add(0x148).writePointer(pathAddr);
    x1Buffer.add(0x200).writePointer(uploadAesKeyAddr);

    const startUploadMedia = new NativeFunction(uploadImageAddr, 'int64', ['pointer', 'pointer']);
    return startUploadMedia(uploadGlobalX0, x1Buffer);
}

// -------------------------基础函数分区-------------------------

// -------------------------全局变量分区-------------------------

// 文本消息全局变量 (new_text.js approach)
var blrX8Addr;
var autoBufferWriteFunc;
var textCgiAddr = ptr(0);
var sendTextMessageAddr = ptr(0);
var textMessageAddr = ptr(0);
var sendMessageCallbackFunc;
var retOneStub = ptr(0);
var fakeVtable = ptr(0);
var pendingInsertMsgAddr = ptr(0);  // 等待buf2resp后清理的insertMsgAddr
var pendingSendMsgType = "";  // 等待buf2resp回调时使用的消息类型
var pendingBuf2RespTaskId = 0;  // 等待buf2resp匹配的taskId
var pendingBuf2RespStartedAt = 0;
var textProtoDataAddr = ptr(0);


// 双方公共使用的地址
var triggerX1Payload;
var triggerX0;
var triggeringStartTask = false;
var req2bufEnterAddr;
var req2bufExitAddr;
var sendFuncAddr;
var sendDirectFuncAddr = ptr(0);
var insertMsgAddr = ptr(0);
var sendMsgType = "";
var buf2RespAddr;
var receiveResponseAddr;
var receiveResponseMode;
var receiverHookReady = false;
var receiverHookStatus = "initializing";
var receiverHookAttempts = 0;
var receiverHookLastError = "";

var realTextSendAsyncAddr;
var realTextSubmitAsyncAddr;
var realTextManagerProviderAddr;
var realTextSendFactoryAddr;
var realTextRequestCtorAddr;
var realTextEncoderAddr;
var realTextResponseAddr;
var realTextReq2BufAddr;
var realTextAutoBufferDataAddr;
var realTextAutoBufferLengthAddr;
var realTextPayloadCtorAddr;
var realTextParseFromArrayAddr;
var realTextPayloadDtorAddr;
var realTextResultDtorAddr;
var realTextFutureDtorAddr;
var nativeRealTextSubmitAsync = null;
var nativeRealTextManagerProvider = null;
var nativeRealTextManagerGetter = null;
var nativeRealTextPayloadCtor = null;
var nativeRealTextParseFromArray = null;
var nativeRealTextPayloadDtor = null;
var nativeRealTextFutureDtor = null;
var nativeRealTextAutoBufferData = null;
var nativeRealTextAutoBufferLength = null;
var realTextSendReady = false;
var realTextSendStatus = "unavailable";
var realTextTraceActive = false;
var realTextTraceEnteredFactory = false;
var realTextTraceFactoryTaskId = 0;
var realTextTraceReachedReq2Buf = false;
var realTextTraceReq2BufTaskIds = [];
var realTextTraceRequest = ptr(0);
var pendingRealTextRequest = ptr(0);
var realTextManualEncoderCaptures = 0;
var realTextEncoderDiagnostics = [];
var realTextLifecycleDiagnostics = {};
var realTextAckHookReady = false;
var pendingRealTextFuture = ptr(0);
var realTextReadyAfter = 0;
var miniProgramSendReady = false;
var classicTextSendReady = false;
var classicSendWindow = false;
var classicSendThreadId = -1;
var classicSendWindowTimer = null;
var miniProgramPendingTaskId = 0;
var classicPendingTaskId = 0;  // [classic-send] 等待 ACK 匹配的克隆任务 taskId
var miniProgramPendingInsertMsgAddr = ptr(0);

var uploadImageAddr;
var cndOnCompleteAddr;
var imgMessageCallbackFunc;
var videoMessageCallbackFunc;

var uploadGetCallbackWrapperAddr;
var uploadGetCallbackWrapperFuncAddr;
var uploadOnCompleteAddr;
var uploadOnCompleteFuncAddr;
var downloadImagAddr;
var startDownloadMedia;
var downloadFileAddr;
var downloadVideoAddr;

var downloadGlobalX0;
var downloadFileX1 = ptr(0)
var fileIdAddr = ptr(0)
var downloadAesKeyAddr = ptr(0)
var filePathAddr = ptr(0)
var fileCdnUrlAddr = ptr(0)
var uploadImageX1 = ptr(0);
var imgCgiAddr = ptr(0);
var sendImgMessageAddr = ptr(0);
var imgMessageAddr = ptr(0);
var uploadGlobalX0 = ptr(0)
var uploadFunc1Addr = ptr(0)
var uploadFunc2Addr = ptr(0)
var imageIdAddr = ptr(0)
var md5Addr = ptr(0)
var uploadAesKeyAddr = ptr(0)
var ImagePathAddr1 = ptr(0)
var uploadCallback = ptr(0)

var videoCgiAddr = ptr(0);
var sendVideoMessageAddr = ptr(0);
var videoMessageAddr = ptr(0);
var uploadVideoX1 = ptr(0);
var videoIdAddr = ptr(0);
var videoPathAddr1 = ptr(0)

// 语音消息全局变量
var voiceMessageCallbackFunc;
var voiceCgiAddr = ptr(0);
var sendVoiceMessageAddr = ptr(0);
var voiceMessageAddr = ptr(0);
var uploadVoiceX1 = ptr(0);
var voiceIdAddr = ptr(0);
var voicePathAddr1 = ptr(0);
var voiceProtoHexGlobal = "";
var voiceDurationGlobal = 0;
var voiceSilkDataLenGlobal = 0;
var voiceAudioDataAddr = ptr(0);


// 发送消息的全局变量
var taskIdGlobal = 0x20000090 // 最好比较大，不和原始的微信消息重复

// 文本消息protobuf全局变量 (从Go直接传入hex编码)
var textProtoHexGlobal = "";
// 图片消息protobuf全局变量 (从Go直接传入hex编码)
var imgProtoHexGlobal = "";
// 视频消息protobuf全局变量 (从Go直接传入hex编码)
var videoProtoHexGlobal = "";
// 回复消息protobuf全局变量 (从Go直接传入hex编码)
var replyProtoHexGlobal = "";
// 文件消息protobuf全局变量 (从Go直接传入hex编码)
var fileProtoHexGlobal = "";
var fileUploadProtoHexGlobal = "";
// uploadappattach protobuf全局变量 (从Go直接传入hex编码)
var appAttachProtoHexGlobal = "";

// 文件消息全局变量
var fileCgiAddr = ptr(0);
var sendFileMessageAddr = ptr(0);
var fileMessageAddr = ptr(0);
var uploadFileIdAddr = ptr(0);
var uploadFileX1 = ptr(0);

// sendfileuploadmsg 全局变量
var fileUploadCgiAddr = ptr(0);
var sendFileUploadMessageAddr = ptr(0);
var fileUploadMessageAddr = ptr(0);

// uploadappattach 全局变量
var appAttachCgiAddr = ptr(0);
var sendAppAttachMessageAddr = ptr(0);
var appAttachMessageAddr = ptr(0);

// 回复消息全局变量
var replyMessageCallbackFunc;
var replyCgiAddr = ptr(0);
var sendReplyMessageAddr = ptr(0);
var replyMessageAddr = ptr(0);

// -------------------------全局变量分区-------------------------


// -------------------------发送文本消息分区-------------------------
// 初始化进行内存的分配
function setupSendTextMessageDynamic() {
    // 动态分配内存

    textCgiAddr = Memory.alloc(128);
    sendTextMessageAddr = Memory.alloc(256);
    textMessageAddr = Memory.alloc(256);
    textProtoDataAddr = Memory.alloc(64 * 1024); // 支持 50KB 分片(uploadappattach)的 protobuf
    // X1 是一次发送任务的可变 payload，必须使用长期存活的自有缓冲区。
    // 复用微信调用栈里的临时 X1 会在稍后发送时变成悬空指针并导致 access violation。
    triggerX1Payload = Memory.alloc(1024);

    // A. 写入字符串内容
    patchString(textCgiAddr, "/cgi-bin/micromsg-bin/newsendmsg");

    // B. 构建 sendTextMessageAddr 结构体 (X24 基址位置)
    sendTextMessageAddr.add(0x00).writeU64(0);
    sendTextMessageAddr.add(0x08).writeU64(0);
    sendTextMessageAddr.add(0x10).writeU64(0);
    sendTextMessageAddr.add(0x18).writeU64(1);
    sendTextMessageAddr.add(0x20).writeU32(taskIdGlobal);
    sendTextMessageAddr.add(0x28).writePointer(textMessageAddr);

    // C. 构建 Message 结构体
    textMessageAddr.add(0x00).writePointer(fakeVtable);
    textMessageAddr.add(0x08).writeU32(taskIdGlobal);
    textMessageAddr.add(0x0c).writeU32(0x20a);
    textMessageAddr.add(0x10).writeU64(0x3);
    textMessageAddr.add(0x18).writePointer(textCgiAddr);
    // Frida 17 在部分 macOS 进程中对 uint64("0x20") 会报 missing argument；
    // 这里是小整数，直接写入等价且不依赖运行时 uint64 helper。
    textMessageAddr.add(0x20).writeU64(0x20);

    console.log("[+] Dynamic Text Message Setup Complete.");
}


// -------------------------发送文件消息分区-------------------------
function setupSendFileMessageDynamic() {
    fileCgiAddr = Memory.alloc(128);
    sendFileMessageAddr = Memory.alloc(256);
    fileMessageAddr = Memory.alloc(256);
    uploadFileIdAddr = Memory.alloc(128);
    uploadFileX1 = Memory.alloc(1024);
    patchString(uploadFileIdAddr, "file_upload_not_init");

    patchString(fileCgiAddr, "/cgi-bin/micromsg-bin/sendappmsg");

    sendFileMessageAddr.add(0x00).writeU64(0);
    sendFileMessageAddr.add(0x08).writeU64(0);
    sendFileMessageAddr.add(0x10).writeU64(0);
    sendFileMessageAddr.add(0x18).writeU64(1);
    sendFileMessageAddr.add(0x20).writeU32(taskIdGlobal);
    sendFileMessageAddr.add(0x28).writePointer(fileMessageAddr);

    fileMessageAddr.add(0x00).writePointer(fakeVtable);
    fileMessageAddr.add(0x08).writeU32(taskIdGlobal);
    fileMessageAddr.add(0x0c).writeU32(0x6e);
    fileMessageAddr.add(0x10).writeU64(0x3);
    fileMessageAddr.add(0x18).writePointer(fileCgiAddr);
    fileMessageAddr.add(0x20).writeU64(0x20);
    fileMessageAddr.add(0x28).writeU64(uint64("0x8000000000000030"));
    fileMessageAddr.add(0x30).writeU64(uint64("0x0000000001010100"));
}

// [4.1.13-classic] 经典文本发送：NativeCallback 伪造 encode 虚方法，绕过 blrX8/req2buf 依赖
function setupClassicTextSend() {
    setupRetOneStub();
    textProtoDataAddr = Memory.alloc(64 * 1024);

    // encode 虚方法槽(+0x10)：序列化器调用 encode(msg, autoBuffer) 时写入我们的 protobuf
    var nativeAutoBufferWrite = new NativeFunction(autoBufferWriteFunc, 'int', ['pointer', 'pointer', 'int']);
    var encodeCallback = new NativeCallback(function (self, autoBuffer) {
        try {
            var protoHex = textProtoHexGlobal;
            if (!protoHex || protoHex.length === 0) return 1;
            var payload = hexToByteArray(protoHex);
            textProtoDataAddr.writeByteArray(payload);
            nativeAutoBufferWrite(autoBuffer, textProtoDataAddr, payload.length);
            console.log("[classic-send] encode 回调注入 protobuf len=" + payload.length);
        } catch (e) {
            console.error("[classic-send] encode 回调失败: " + e.message);
        }
        return 1;
    }, 'int', ['pointer', 'pointer']);
    fakeVtable.add(0x10).writePointer(encodeCallback);

    // 文本消息结构（CGI/消息对象/任务模板）
    setupSendTextMessageDynamic();

    // x0 捕获：任意后台任务（心跳等）经过 sendFunc+0x10 即可获得真实上下文
    AttachSendFunc();
    // payload 注入点（4.1.13 blrX8 等价）：序列化器 vtable+0x10 派发前换缓冲内容
    attachEncodeInject();


    classicTextSendReady = true;
    console.log("[classic-send] 经典文本发送已就绪，等待 StartTask 上下文捕获");
}

// [4.1.13] 序列化注入 v2：挂 autoBufferWrite 本体（所有任务序列化必经）。
// 注入旗标窗口期内首次 write 调用极大概率是本任务序列化——直接换写内容为我们的 protobuf。
// 误伤面：1.5s 窗口内恰好有其他任务序列化（内容层错误不崩进程，服务器拒收而已）。
var encodeInjectHitCount = 0;
var encodeInjectWindowHits = 0;
var encodeInjected = false;
function attachEncodeInject() {
    var handler = {
        onEnter: function () {
            encodeInjectHitCount++;
            if (!classicSendWindow || encodeInjected) return;
            encodeInjectWindowHits++;
            var protoHex = textProtoHexGlobal;
            if (!protoHex || protoHex.length === 0) return;
            var payload = hexToByteArray(protoHex);
            textProtoDataAddr.writeByteArray(payload);
            // write(autoBuffer, data, len) —— 换写内容与长度
            this.context.x1 = textProtoDataAddr;
            this.context.x2 = ptr(payload.length);
            encodeInjected = true;
            console.log("[classic-inject] 命中! 换写 " + payload.length + " 字节 thread=" + this.threadId + " 原len=" + this.context.x2 + " autoBuffer=" + this.context.x0);
        }
    };
    // 热路径碰撞重试：attach 瞬间若有线程正执行在重定位窗口内会报 unable to intercept（登录风暴期实测），
    // 隔 300ms 重试最多 6 次；失败仅禁用经典发送注入，不影响接收。
    var lastError = null;
    for (var attempt = 1; attempt <= 6; attempt++) {
        try {
            Interceptor.attach(autoBufferWriteFunc, handler);
            console.log("[classic-inject] write注入已挂载 @" + autoBufferWriteFunc + " (尝试 " + attempt + "/6)");
            return;
        } catch (e) {
            lastError = e;
            console.log("[classic-inject] 第 " + attempt + " 次挂载失败: " + e.message + "，300ms 后重试");
            Thread.sleep(0.3);
        }
    }
    console.log("[classic-inject] 注入点 6 次重试后仍失败: " + (lastError && lastError.message));
}


// [4.1.13] 总提交口(0x62cf4e4)覆写：taskId 匹配时把 wire protobuf 写入 x1 缓冲
var submitOwState = { diag: 0 };
function attachSubmitOverwrite() {
    Interceptor.attach(baseAddr.add(0x62cf4e4), {
        onEnter: function () {
            // 诊断模式：前6次记录 x0/x1 头部，找 taskId 位置
            if (submitOwState.diag < 6) {
                submitOwState.diag += 1;
                try {
                    var x0h = hexdump(this.context.x0, { length: 32, header: false, ansi: false }).split('\n')[0];
                    var x1h = hexdump(this.context.x1, { length: 32, header: false, ansi: false }).split('\n')[0];
                    console.log('[submit-ow diag' + submitOwState.diag + '] x0=' + this.context.x0 + ' [' + x0h + '] x1=' + this.context.x1 + ' [' + x1h + ']');
                } catch (e) {}
            }
        }
    });
    console.log('[submit-ow] 总提交口监控已挂载 @0x62cf4e4');
}


// [4.1.13] 序列化器入口(0x2ea7bf0)消息注册：把 x2(消息对象)换成 textMessageAddr
// 假消息 vtable 的 encode 槽(NativeCallback)会写入 protobuf 并返回1
function attachSerializerSwap() {
    Interceptor.attach(baseAddr.add(0x2ea7c00), {
        onEnter: function () {
            if (!classicSendWindow || this.threadId !== classicSendThreadId) return;
            console.log("[classic-swap] 序列化器入口命中! 原 x2=" + this.context.x2 + " 换为 " + textMessageAddr);
            this.context.x2 = textMessageAddr;
        }
    });
    console.log("[classic-swap] 序列化器入口注册已挂载 @0x2ea7c00");
}

function setupMiniProgramSend() {
    setupRetOneStub();
    textProtoDataAddr = Memory.alloc(64 * 1024);
    triggerX1Payload = Memory.alloc(1024);
    setupSendFileMessageDynamic();
    attachBlrX8Hook();
    AttachSendFunc();
    attachReq2buf();
    miniProgramSendReady = true;
    console.log("[mini-program-send] 小程序卡片发送 Hook 已启用，等待 StartTask 上下文");
}

function triggerSendFileMessage(taskId, sender, receiver, protoHex, payloadHex) {
    return triggerSendMediaMessage(taskId, sender, receiver, protoHex, payloadHex, "file");
}

function triggerSendMiniProgram(taskId, sender, receiver, protoHex, payloadHex) {
    return triggerSendMediaMessage(taskId, sender, receiver, protoHex, payloadHex, "mini_program");
}

function getMiniProgramSendStatus() {
    if (!miniProgramSendReady) return "unavailable";
    if (miniProgramPendingTaskId !== 0) return "busy";
    if (!triggerX0 || !isReadablePointer(triggerX0)) return "waiting_context";
    return "ready";
}

function cancelPendingMiniProgram(taskId) {
    if (miniProgramPendingTaskId === 0 || miniProgramPendingTaskId !== Number(taskId)) return false;
    if (!miniProgramPendingInsertMsgAddr.isNull()) {
        miniProgramPendingInsertMsgAddr.writeU64(0);
        miniProgramPendingInsertMsgAddr = ptr(0);
    }
    miniProgramPendingTaskId = 0;
    return true;
}

function triggerUploadFile(receiver, md5, filePath, payloadHex) {
    return fillUploadX1AndStart(uploadFileIdAddr, ImagePathAddr1, uploadFileX1, receiver, md5, filePath, payloadHex);
}

// -------------------------sendfileuploadmsg分区-------------------------
function setupSendFileUploadMessageDynamic() {
    fileUploadCgiAddr = Memory.alloc(128);
    sendFileUploadMessageAddr = Memory.alloc(256);
    fileUploadMessageAddr = Memory.alloc(256);

    patchString(fileUploadCgiAddr, "/cgi-bin/micromsg-bin/sendfileuploadmsg");

    sendFileUploadMessageAddr.add(0x00).writeU64(0);
    sendFileUploadMessageAddr.add(0x08).writeU64(0);
    sendFileUploadMessageAddr.add(0x10).writeU64(0);
    sendFileUploadMessageAddr.add(0x18).writeU64(1);
    sendFileUploadMessageAddr.add(0x20).writeU32(taskIdGlobal);
    sendFileUploadMessageAddr.add(0x28).writePointer(fileUploadMessageAddr);

    fileUploadMessageAddr.add(0x00).writePointer(fakeVtable);
    fileUploadMessageAddr.add(0x08).writeU32(taskIdGlobal);
    fileUploadMessageAddr.add(0x0c).writeU32(0x6e);
    fileUploadMessageAddr.add(0x10).writeU64(0x3);
    fileUploadMessageAddr.add(0x18).writePointer(fileUploadCgiAddr);
    fileUploadMessageAddr.add(0x20).writeU64(0x20);
    fileUploadMessageAddr.add(0x28).writeU64(uint64("0x8000000000000030"));
    fileUploadMessageAddr.add(0x30).writeU64(uint64("0x0000000001010100"));
}

function triggerSendFileUploadMessage(taskId, sender, receiver, protoHex, payloadHex) {
    return triggerSendMediaMessage(taskId, sender, receiver, protoHex, payloadHex, "fileupload");
}

// -------------------------uploadappattach分区-------------------------
function setupSendAppAttachMessageDynamic() {
    appAttachCgiAddr = Memory.alloc(128);
    sendAppAttachMessageAddr = Memory.alloc(256);
    appAttachMessageAddr = Memory.alloc(256);

    patchString(appAttachCgiAddr, "/cgi-bin/micromsg-bin/uploadappattach");

    sendAppAttachMessageAddr.add(0x00).writeU64(0);
    sendAppAttachMessageAddr.add(0x08).writeU64(0);
    sendAppAttachMessageAddr.add(0x10).writeU64(0);
    sendAppAttachMessageAddr.add(0x18).writeU64(1);
    sendAppAttachMessageAddr.add(0x20).writeU32(taskIdGlobal);
    sendAppAttachMessageAddr.add(0x28).writePointer(appAttachMessageAddr);

    appAttachMessageAddr.add(0x00).writePointer(fakeVtable);
    appAttachMessageAddr.add(0x08).writeU32(taskIdGlobal);
    appAttachMessageAddr.add(0x0c).writeU32(0x6e);
    appAttachMessageAddr.add(0x10).writeU64(0x3);
    appAttachMessageAddr.add(0x18).writePointer(appAttachCgiAddr);
    appAttachMessageAddr.add(0x20).writeU64(0x25);
    appAttachMessageAddr.add(0x28).writeU64(uint64("0x8000000000000030"));
    appAttachMessageAddr.add(0x30).writeU64(uint64("0x0000000001010100"));
}

function triggerUploadAppAttach(taskId, sender, receiver, protoHex, payloadHex) {
    return triggerSendMediaMessage(taskId, sender, receiver, protoHex, payloadHex, "appattach");
}

// -------------------------发送文件消息分区-------------------------



// 创建一个只返回1的小函数stub
function setupRetOneStub() {
    retOneStub = Memory.alloc(Process.pageSize);
    Memory.patchCode(retOneStub, 8, code => {
        // MOV W0, #1 = 0x52800020, RET = 0xD65F03C0 (little-endian)
        code.writeByteArray([0x20, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6]);
    });
    console.log("[+] Return-1 stub created at: " + retOneStub);

    // 构造假vtable：所有槽位指向retOneStub，这样mars对我们伪造结构做虚调用时不会崩溃
    fakeVtable = Memory.alloc(512);
    for (var i = 0; i < 64; i++) {
        fakeVtable.add(i * 8).writePointer(retOneStub);
    }
    console.log("[+] Fake vtable created at: " + fakeVtable);
}

function attachBlrX8Hook() {
    console.log("[+] Hooking BLR X8 at: " + blrX8Addr);

    var nativeAutoBufferWrite = new NativeFunction(autoBufferWriteFunc, 'int', ['pointer', 'pointer', 'int']);

    Interceptor.attach(blrX8Addr, {
        onEnter: function(args) {
            var currentTaskId = this.context.x20.toUInt32();
            if (currentTaskId !== taskIdGlobal) {
                return;
            }

            console.log("[+] BLR X8 命中! taskId=" + currentTaskId + " sendMsgType=" + sendMsgType);

            var autoBuffer = this.context.x1;
            var protoHex = "";

            if (sendMsgType === "text") {
                protoHex = textProtoHexGlobal;
            } else if (sendMsgType === "img") {
                protoHex = imgProtoHexGlobal;
            } else if (sendMsgType === "video") {
                protoHex = videoProtoHexGlobal;
            } else if (sendMsgType === "reply") {
                protoHex = replyProtoHexGlobal;
            } else if (sendMsgType === "file") {
                protoHex = fileProtoHexGlobal;
            } else if (sendMsgType === "fileupload") {
                protoHex = fileUploadProtoHexGlobal;
			} else if (sendMsgType === "appattach") {
				protoHex = appAttachProtoHexGlobal;
			} else if (sendMsgType === "mini_program") {
				protoHex = fileProtoHexGlobal;
            } else if (sendMsgType === "voice") {
                protoHex = voiceProtoHexGlobal;
            }

            if (!protoHex || protoHex.length === 0) {
                console.error("[!] protoHex 为空, sendMsgType=" + sendMsgType);
                return;
            }

            var finalPayload = hexToByteArray(protoHex);
            textProtoDataAddr.writeByteArray(finalPayload);

            // 调用 autoBufferWrite(autoBuffer, data, len) 填充 v133
            nativeAutoBufferWrite(autoBuffer, textProtoDataAddr, finalPayload.length);
            console.log("[+] autoBufferWrite 调用完成, protobuf长度: " + finalPayload.length);

            // 将 X8 指向 retOneStub，这样 BLR X8 只会返回1，不执行原始逻辑
            this.context.x8 = retOneStub;
        }
    });
}


function zeroMemory(addr, size) {
    addr.writeByteArray(new Uint8Array(size));
}

function readProtoVarint(bytes, offset) {
    var value = 0;
    var scale = 1;
    for (var i = 0; i < 10 && offset + i < bytes.length; i++) {
        var current = bytes[offset + i];
        value += (current & 0x7f) * scale;
        if ((current & 0x80) === 0) return { value: value, next: offset + i + 1 };
        scale *= 128;
    }
    return null;
}

function summarizeProtoShape(bytes, depth) {
    var fields = [];
    var offset = 0;
    var fieldCount = 0;
    while (offset < bytes.length && fieldCount++ < 64) {
        var key = readProtoVarint(bytes, offset);
        if (!key || key.value === 0) return fields.concat(["invalid@" + offset]).join(",");
        offset = key.next;
        var fieldNumber = Math.floor(key.value / 8);
        var wireType = key.value % 8;
        if (wireType === 0) {
            var scalar = readProtoVarint(bytes, offset);
            if (!scalar) return fields.concat([fieldNumber + ":bad-varint"]).join(",");
            fields.push(fieldNumber + ":v" + (scalar.value <= 16 ? "=" + scalar.value : ""));
            offset = scalar.next;
        } else if (wireType === 1) {
            fields.push(fieldNumber + ":i64");
            offset += 8;
        } else if (wireType === 2) {
            var size = readProtoVarint(bytes, offset);
            if (!size || size.value < 0 || size.next + size.value > bytes.length) {
                return fields.concat([fieldNumber + ":bad-len"]).join(",");
            }
            var start = size.next;
            var end = start + size.value;
            var nested = "";
            if (depth === 0 && fieldNumber === 2) {
                nested = "{" + summarizeProtoShape(bytes.subarray(start, end), depth + 1) + "}";
            }
            fields.push(fieldNumber + ":len=" + size.value + nested);
            offset = end;
        } else if (wireType === 5) {
            fields.push(fieldNumber + ":i32");
            offset += 4;
        } else {
            return fields.concat([fieldNumber + ":wire=" + wireType]).join(",");
        }
        if (offset > bytes.length) return fields.concat(["truncated"]).join(",");
    }
    return fields.join(",");
}

function findTextRequestInTaskMap(session, taskId) {
    var end = session.add(0x60);
    var node = readPointerIfReadable(end);
    for (var i = 0; node && !node.isNull() && !node.equals(end) && i < 256; i++) {
        if (!isReadablePointer(node.add(0x28))) return null;
        var key = node.add(0x20).readU32();
        if (key === taskId) return readPointerIfReadable(node.add(0x28));
        node = readPointerIfReadable(node.add(key < taskId ? 0x8 : 0x0));
    }
    return null;
}

function createRealTextSubmitTrampoline(target) {
    // Three pointer-sized fields force ARM64's indirect-result ABI while keeping
    // the native function's four explicit parameters intact.
    var invokeSubmit = new NativeFunction(target,
        ['pointer', 'pointer', 'pointer'],
        ['pointer', 'pointer', 'pointer', 'pointer']);
    return function (manager, payload, options1, options2, result) {
        var returned = invokeSubmit(manager, payload, options1, options2);
        result.writePointer(returned[0]);
        result.add(Process.pointerSize).writePointer(returned[1]);
    };
}

function releasePendingRealTextFuture() {
    if (pendingRealTextFuture.isNull()) return;
    var future = pendingRealTextFuture;
    pendingRealTextFuture = ptr(0);
    setTimeout(function () {
        try {
            nativeRealTextFutureDtor(future);
        } catch (error) {
            console.error("[experimental-send] future 释放失败: " + error);
        }
    }, 0);
}

function getRealTextManager() {
    var provider = nativeRealTextManagerProvider();
    if (!provider || provider.isNull()) {
        throw new Error("text manager provider unavailable");
    }
    if (nativeRealTextManagerGetter === null) {
        var vtable = provider.readPointer();
        var getterAddress = vtable.isNull() ? ptr(0) : vtable.add(0x18).readPointer();
        if (!getterAddress || getterAddress.isNull()) {
            throw new Error("text manager getter unavailable");
        }
        nativeRealTextManagerGetter = new NativeFunction(getterAddress, 'pointer', ['pointer']);
    }
    var manager = nativeRealTextManagerGetter(provider);
    if (!manager || manager.isNull()) {
        throw new Error("text manager unavailable");
    }
    return manager;
}

function isRealTextManagerProviderReady() {
    if (nativeRealTextManagerProvider === null) return false;
    try {
        var provider = nativeRealTextManagerProvider();
        return !!provider && !provider.isNull();
    } catch (error) {
        return false;
    }
}

function readRealTextAutoBuffer(autoBuffer) {
    if (!autoBuffer || autoBuffer.isNull()) return null;
    try {
        var dataAddress = nativeRealTextAutoBufferData(autoBuffer, 0);
        var lengthValue = nativeRealTextAutoBufferLength(autoBuffer);
        var length = Number(lengthValue.toString());
        if (!dataAddress || dataAddress.isNull() || length <= 0 || length > MAX_FRIDA_MESSAGE_BYTES) {
            return null;
        }
        var data = dataAddress.readByteArray(length);
        return data ? { data: data, length: length } : null;
    } catch (error) {
        return null;
    }
}

function readReceiveAutoBuffer(autoBuffer) {
    if (!autoBuffer || autoBuffer.isNull()) return null;
    try {
        var dataGetter = nativeRealTextAutoBufferData;
        var lengthGetter = nativeRealTextAutoBufferLength;
        if (dataGetter === null || lengthGetter === null) {
            if (realTextAutoBufferDataAddr.isNull() || realTextAutoBufferLengthAddr.isNull()) return null;
            dataGetter = new NativeFunction(realTextAutoBufferDataAddr, 'pointer', ['pointer', 'int']);
            lengthGetter = new NativeFunction(realTextAutoBufferLengthAddr, 'uint64', ['pointer']);
        }
        var dataAddress = dataGetter(autoBuffer, 0);
        var lengthValue = lengthGetter(autoBuffer);
        var length = Number(lengthValue.toString());
        if (!dataAddress || dataAddress.isNull() || length <= 0 || length > MAX_FRIDA_MESSAGE_BYTES) {
            return null;
        }
        var data = dataAddress.readByteArray(length);
        return data ? { data: data, length: length } : null;
    } catch (error) {
        return null;
    }
}

function setupRealTextSend() {
    var requiredAddresses = [
        realTextSendAsyncAddr,
        realTextSubmitAsyncAddr,
        realTextManagerProviderAddr,
        realTextSendFactoryAddr,
        realTextRequestCtorAddr,
        realTextEncoderAddr,
        realTextResponseAddr,
        realTextAutoBufferDataAddr,
        realTextAutoBufferLengthAddr,
        realTextPayloadCtorAddr,
        realTextParseFromArrayAddr,
        realTextFutureDtorAddr,
    ];
    if (requiredAddresses.some(function (address) { return address.isNull(); })) {
        console.error("[experimental-send] 当前微信版本未配置真实工厂文本发送地址");
        return false;
    }
    nativeRealTextSubmitAsync = createRealTextSubmitTrampoline(realTextSubmitAsyncAddr);
    nativeRealTextManagerProvider = new NativeFunction(realTextManagerProviderAddr, 'pointer', []);
    nativeRealTextPayloadCtor = new NativeFunction(realTextPayloadCtorAddr, 'void', ['pointer']);
    nativeRealTextParseFromArray = new NativeFunction(realTextParseFromArrayAddr, 'int', ['pointer', 'pointer', 'int']);
    nativeRealTextPayloadDtor = realTextPayloadDtorAddr.isNull() ? null : new NativeFunction(realTextPayloadDtorAddr, 'void', ['pointer']);
    nativeRealTextFutureDtor = new NativeFunction(realTextFutureDtorAddr, 'void', ['pointer']);
    nativeRealTextAutoBufferData = new NativeFunction(realTextAutoBufferDataAddr, 'pointer', ['pointer', 'int']);
    nativeRealTextAutoBufferLength = new NativeFunction(realTextAutoBufferLengthAddr, 'uint64', ['pointer']);
    Interceptor.attach(realTextSubmitAsyncAddr, {
        onEnter: function (args) {
            if (!realTextTraceActive) return;
            realTextLifecycleDiagnostics.submitEntered = true;
        },
        onLeave: function () {
            if (realTextTraceActive) realTextLifecycleDiagnostics.submitReturned = true;
        },
    });
    Interceptor.attach(realTextSendFactoryAddr, {
        onEnter: function () {
            if (!realTextTraceActive) return;
            realTextTraceEnteredFactory = true;
            console.log("[experimental-send] 已进入微信真实文本工厂");
        },
        onLeave: function (retval) {
            if (!realTextTraceActive) return;
            realTextTraceFactoryTaskId = retval.toUInt32();
            realTextLifecycleDiagnostics.factoryTaskId = realTextTraceFactoryTaskId;
            console.log("[experimental-send] 微信真实文本工厂返回 taskId=" + realTextTraceFactoryTaskId);
            if (realTextTraceFactoryTaskId !== 0) {
                pendingBuf2RespTaskId = realTextTraceFactoryTaskId;
                pendingBuf2RespStartedAt = Date.now();
                pendingRealTextRequest = realTextTraceRequest;
                pendingSendMsgType = "text";
            }
            if (realTextTraceReq2BufTaskIds.indexOf(realTextTraceFactoryTaskId) !== -1) {
                realTextTraceReachedReq2Buf = true;
                console.log("[experimental-send] 文本任务已在工厂返回前进入 Req2Buf taskId=" +
                    realTextTraceFactoryTaskId);
            }
        },
    });
    Interceptor.attach(realTextRequestCtorAddr, {
        onEnter: function (args) {
            if (!realTextTraceActive) return;
            realTextTraceRequest = args[0];
        },
    });
    Interceptor.attach(realTextEncoderAddr, {
        onEnter: function (args) {
            var request = args[0];
            var isBackground = (!realTextTraceRequest.isNull() && request.equals(realTextTraceRequest)) ||
                (!pendingRealTextRequest.isNull() && request.equals(pendingRealTextRequest));
            if (!isBackground && realTextManualEncoderCaptures >= 4) return;
            this.captureTextEncoding = true;
            this.encodingOrigin = isBackground ? "background" : "manual";
            this.encodingTaskId = isBackground ? (realTextTraceFactoryTaskId || pendingBuf2RespTaskId) : 0;
            this.encodingBuffer = args[1];
            if (isBackground) realTextLifecycleDiagnostics.encoderReached = true;
            if (!isBackground) realTextManualEncoderCaptures++;
        },
        onLeave: function () {
            if (!this.captureTextEncoding) return;
            var encoded = readRealTextAutoBuffer(this.encodingBuffer);
            if (!encoded) return;
            var shape = summarizeProtoShape(new Uint8Array(encoded.data), 0);
            realTextEncoderDiagnostics.push({
                origin: this.encodingOrigin,
                taskId: this.encodingTaskId,
                length: encoded.length,
                shape: shape,
            });
            if (realTextEncoderDiagnostics.length > 8) realTextEncoderDiagnostics.shift();
            console.log("[experimental-send] 文本编码摘要 origin=" + this.encodingOrigin +
                " taskId=" + this.encodingTaskId + " len=" + encoded.length + " shape=" + shape);
        },
    });
    Interceptor.attach(realTextResponseAddr, {
        onEnter: function (args) {
            var request = args[0];
            var autoBuffer = args[1];
            if (pendingBuf2RespTaskId === 0 || pendingRealTextRequest.isNull() ||
                !request.equals(pendingRealTextRequest)) return;

            var responseTaskId = pendingBuf2RespTaskId;
            realTextLifecycleDiagnostics.responseReached = true;

            var response = readRealTextAutoBuffer(autoBuffer);
            var responseBytes = response ? response.data : null;

            var msgType = pendingSendMsgType;
            clearPendingTextState();
            if (!responseBytes) {
                console.error("[experimental-send] 文本 ACK 读取失败 taskId=" + responseTaskId);
                send({ type: "buf2resp", msg_type: msgType, data: [] });
                return;
            }

            var bytes = new Uint8Array(responseBytes);
            var ackHexParts = [];
            for (var bi = 0; bi < Math.min(bytes.length, 96); bi++) ackHexParts.push(bytes[bi].toString(16).padStart(2, '0'));
            console.log("[experimental-send] 收到文本 ACK taskId=" + responseTaskId + " len=" + bytes.length + " hex=" + ackHexParts.join(' '));
            send({ type: "buf2resp", msg_type: msgType, data: Array.from(bytes) });
        },
    });
    if (realTextReq2BufAddr.isNull()) {
        console.log("[experimental-send] Req2Buf 诊断 Hook 未配置（该微信版本未定位），跳过");
    } else Interceptor.attach(realTextReq2BufAddr, {
        onEnter: function (args) {
            var req2BufTaskId = args[1].toUInt32();
            if (realTextTraceActive) realTextTraceReq2BufTaskIds.push(req2BufTaskId);
            var tracedTaskId = realTextTraceFactoryTaskId || pendingBuf2RespTaskId;
            if (tracedTaskId === 0 || req2BufTaskId !== tracedTaskId) return;
            realTextTraceReachedReq2Buf = true;
            var mappedRequest = findTextRequestInTaskMap(args[0], req2BufTaskId);
            var mapHit = mappedRequest !== null && !mappedRequest.isNull();
            realTextLifecycleDiagnostics.req2bufTaskId = req2BufTaskId;
            realTextLifecycleDiagnostics.req2bufMapHit = mapHit;
            console.log("[experimental-send] 文本任务进入 Req2Buf taskId=" + req2BufTaskId +
                " mapHit=" + mapHit);
        },
    });
    realTextAckHookReady = true;
    realTextSendReady = true;
    realTextSendStatus = "ready";
    realTextReadyAfter = Date.now() + 15000;
    console.log("[experimental-send] 仅启用真实工厂文本发送；旧 Req2Buf/map 注入与媒体发送保持禁用");
    return true;
}


// [4.1.13-schema-matrix] 文本消息 protobuf 变体构造器
function pbVarint(value) {
    var out = [];
    var v = value >>> 0;
    while (true) {
        var b = v & 0x7f;
        v = v >>> 7;
        out.push(v ? (b | 0x80) : b);
        if (!v) break;
    }
    return out;
}
function pbVarint64(value) {
    var out = [];
    var v = BigInt(value);
    while (v > 0n) {
        var b = Number(v & 0x7fn);
        v = v >> 7n;
        out.push(v > 0n ? (b | 0x80) : b);
    }
    return out.length ? out : [0];
}
function pbTag(field, wire) {
    return pbVarint((field << 3) | wire);
}
function pbString(field, str) {
    var utf8 = unescape(encodeURIComponent(str));
    var out = pbTag(field, 2);
    out = out.concat(pbVarint(utf8.length));
    for (var i = 0; i < utf8.length; i++) out.push(utf8.charCodeAt(i) & 0xff);
    return out;
}
function pbVarintField(field, value) {
    return pbTag(field, 0).concat(pbVarint64(value));
}
function buildTextProtoVariant(variant, receiver, content, atUser) {
    var xml = "<msgsource>";
    if (atUser) xml += "<atuserlist>" + atUser + "</atuserlist>";
    xml += "<alnode><fr>1</fr></alnode></msgsource>";
    var ts = Math.floor(Date.now() / 1000);
    var msgId = BigInt(Math.floor(Math.random() * 0x3fffffffff)) | (1n << 34n);
    var body, outer;
    switch (variant) {
        case 2: // 观测形状直译：1=内容 2=类型 37=接收方 38=xml 39=?
            outer = pbString(1, content)
                .concat(pbVarintField(2, 1))
                .concat(pbString(37, receiver))
                .concat(pbString(38, xml))
                .concat(pbString(39, ""));
            break;
        case 3: // 33/34 附近字段
            outer = pbString(1, content)
                .concat(pbVarintField(2, 1))
                .concat(pbVarintField(33, ts))
                .concat(pbVarintField(34, msgId))
                .concat(pbString(37, receiver));
            break;
        case 4: // 旧嵌套但 receiver 平铺
            body = pbString(1, receiver)
                .concat(pbString(2, content))
                .concat(pbVarintField(3, 1))
                .concat(pbVarintField(4, ts))
                .concat(pbVarintField(5, msgId))
                .concat(pbString(6, xml));
            outer = pbVarintField(1, 1).concat(pbTag(2, 2)).concat(pbVarint(body.length)).concat(body);
            break;
        case 5: // 新形状 + receiver 双位置
            body = pbString(2, content);
            outer = pbString(1, content)
                .concat(pbVarintField(2, 1))
                .concat(pbString(37, receiver))
                .concat(pbString(38, xml))
                .concat(pbVarintField(33, ts))
                .concat(pbVarintField(34, msgId));
            break;
        default:
            return null;
    }
    return outer;
}


// [4.1.13] libc++ std::string 写入（24字节布局：短串=23数据+1长度<<1；长串=ptr/size/cap|MSB）
function writeLibcxxString(addr, str) {
    zeroMemory(addr, 0x18);
    var utf8 = unescape(encodeURIComponent(String(str)));
    var len = utf8.length;
    if (len <= 23) {
        var bytes = [];
        for (var i = 0; i < len; i++) bytes.push(utf8.charCodeAt(i) & 0xff);
        addr.writeByteArray(bytes);
        addr.add(23).writeU8(len << 1);
        return true;
    }
    var buf = Memory.alloc(len + 1);
    var bytes = [];
    for (var i = 0; i < len; i++) bytes.push(utf8.charCodeAt(i) & 0xff);
    buf.writeByteArray(bytes);
    buf.add(len).writeU8(0);
    addr.writePointer(buf);
    addr.add(8).writeU64(len);
    addr.add(16).writeU64(uint64("0x8000000000000000").or(uint64(len)));
    return true;
}


// [classic-send] 0x1A0 任务模板（来自上游验证布局）+ taskId 嵌入
function buildClassicTextX1(taskId) {
    var t = [
        0x0A, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x40, 0xEC, 0x0E, 0x12, 0x01, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
        0x00, 0x01, 0x01, 0x01, 0x00, 0xAA, 0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xAA, 0xAA, 0xAA,
        0xFF, 0xFF, 0xFF, 0xFF, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0A, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6C, 0x74, 0x2D,
        0x6C, 0x6F, 0x6E, 0x67, 0x6C, 0x69, 0x6E, 0x6B, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x10,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    t[0] = taskId & 0xff;
    t[1] = (taskId >> 8) & 0xff;
    t[2] = (taskId >> 16) & 0xff;
    t[3] = (taskId >> 24) & 0xff;
    var hex = '';
    for (var i = 0; i < t.length; i++) hex += t[i].toString(16).padStart(2, '0');
    return hex;
}




// [classic-clone] 克隆真实任务 x1 → 重定位内部指针 → 改 taskId/CGI → MMStartTask
var lastRealX1Bytes = null;
var lastRealX1Addr = null;
function triggerClassicCloneSend(taskId, receiver, content, protoHex) {
    try {
        var origBytes = hexToByteArray(lastRealX1Bytes);
        var origBase = lastRealX1Addr;
        var buf = Memory.alloc(origBytes.length + 0x40);
        buf.writeByteArray(origBytes);
        // 重定位：克隆体内指向原始缓冲内部的指针平移到新缓冲（指针算术避免 UInt64 类型问题）
        var origPtr = ptr(lastRealX1Addr.toString());
        for (var off = 0; off + 8 <= origBytes.length; off += 8) {
            try {
                var raw = buf.add(off).readU64();
                var vPtr = ptr('0x' + raw.toString(16));
                var delta = vPtr.sub(origPtr).toInt32();
                if (delta >= 0 && delta < origBytes.length) {
                    buf.add(off).writePointer(buf.add(delta));
                }
            } catch (e) { /* 非法指针值跳过 */ }
        }
        // 任务字段覆盖
        buf.add(0).writeU32(taskId);
        if (!textCgiAddr || textCgiAddr.isNull()) return "fail: cgi 未初始化";
        buf.add(0x18).writePointer(textCgiAddr);
        // cmdId 换成 newsendmsg 的 0x303（微信按 cmdId 路由到 CGI 处理器，不换会 0x0 崩溃）
        buf.add(0x04).writeU32(0x303);
        buf.add(0x60).writeU32(0x303);
        // 注册消息对象（带 fakeVtable，encode 槽由注入点接管）供序列化器回调
        textMessageAddr.add(0x00).writePointer(fakeVtable);
        textMessageAddr.add(0x08).writeU32(taskId);
        textMessageAddr.add(0x0c).writeU32(0x20a);
        textMessageAddr.add(0x18).writePointer(textCgiAddr);
        sendTextMessageAddr.add(0x20).writeU32(taskId);
        sendTextMessageAddr.add(0x28).writePointer(textMessageAddr);
        textProtoHexGlobal = protoHex;
        taskIdGlobal = taskId;
        encodeInjected = false;
        var MMStartTask = new NativeFunction(sendFuncAddr, 'int64', ['pointer', 'pointer']);
        triggeringStartTask = true;
        classicSendWindow = true;
        classicSendThreadId = Process.getCurrentThreadId();
        // 窗口保持到定时器到期：MMStartTask 仅入队，序列化在 stn 工作线程异步发生，
        // finally 立即关窗会错过注入点。命中或 1.5s 后关闭。
        if (classicSendWindowTimer !== null) {
            clearTimeout(classicSendWindowTimer);
        }
        classicSendWindowTimer = setTimeout(function () {
            classicSendWindow = false;
            classicSendWindowTimer = null;
            console.log("[classic-clone] 注入窗口到期: 窗口期命中 " + encodeInjectWindowHits + " 次 (注入点累计 " + encodeInjectHitCount + ")");
        }, 1500);
        try {
            var result = MMStartTask(triggerX0, buf);
            console.log("[classic-clone] MMStartTask 返回 " + result + " taskId=" + taskId + " receiver=" + receiver);
            if (result == 1) {
                // 登记 ACK 等待：接收点命中同 taskId 时回 buf2resp；25s 自清理防泄漏
                classicPendingTaskId = taskId;
                setTimeout(function () {
                    if (classicPendingTaskId === taskId) {
                        classicPendingTaskId = 0;
                        console.log("[classic-clone] ACK 等待超时清理 taskId=" + taskId);
                    }
                }, 25000);
            }
            return "submitted:" + taskId;
        } finally {
            triggeringStartTask = false;
        }
    } catch (e) {
        return "fail: " + e.message;
    }
}

function triggerSendTextMessage(taskId, receiver, content, atUser, protoHex, payloadHex) {
    // [4.1.13] 优先克隆式经典路径：克隆最近真实任务的 x1 模板（4.1.13 布局自动正确）
    if (classicTextSendReady && triggerX0 && lastRealX1Bytes && lastRealX1Addr) {
        var cloneResult = triggerClassicCloneSend(taskId, receiver, content, protoHex);
        console.log("[classic-send] 克隆路径结果: " + cloneResult);
        return cloneResult;
    }
    if (!realTextSendReady || !realTextAckHookReady) {
        return "fail: real text sender or ACK hook unavailable";
    }
    if (!protoHex || protoHex.length === 0 || (protoHex.length % 2) !== 0) {
        return "fail: invalid text protobuf";
    }
    if (pendingBuf2RespTaskId !== 0) {
        if (pendingBuf2RespStartedAt !== 0 && Date.now() - pendingBuf2RespStartedAt > 20000) {
            clearPendingTextState();
        } else {
            return "fail: another send is awaiting ack";
        }
    }

    var protoBytes = hexToByteArray(protoHex);
    // [4.1.13-schema-matrix] 内容前缀 #vN# 触发变体构造（绕过 Go 旧 schema）
    var vm = content.match(/^#v(\d+)#([\s\S]*)$/);
    if (vm) {
        var variant = parseInt(vm[1], 10);
        var realContent = vm[2];
        var rebuilt = buildTextProtoVariant(variant, receiver, realContent, atUser);
        if (rebuilt) {
            protoBytes = rebuilt;
            console.log("[variant] 使用变体 v" + variant + " 重建 protobuf，长度=" + protoBytes.length);
        }
    }
    var protoAddr = Memory.alloc(protoBytes.length);
    var state = Memory.alloc(0x90);
    var future = Memory.alloc(0x20);
    var payload = state.add(0x20);
    var payloadConstructed = false;
    var stage = "allocate";

    zeroMemory(state, 0x90);
    zeroMemory(future, 0x20);
    protoAddr.writeByteArray(protoBytes);

    try {
        stage = "payload-constructor";
        nativeRealTextPayloadCtor(payload);
        payloadConstructed = true;
        stage = "protobuf-parse";
        if (nativeRealTextParseFromArray(payload, protoAddr, protoBytes.length) !== 1) {
            return "fail: WeChat rejected text protobuf";
        }

        stage = "async-submit";
        realTextTraceActive = true;
        realTextTraceEnteredFactory = false;
        realTextTraceFactoryTaskId = 0;
        realTextTraceReachedReq2Buf = false;
        realTextTraceReq2BufTaskIds = [];
        realTextTraceRequest = ptr(0);
        realTextLifecycleDiagnostics = {
            submissionPath: "async-no-wait",
            factoryTaskId: 0,
            req2bufTaskId: 0,
            req2bufMapHit: false,
            encoderReached: false,
            responseReached: false,
            submitEntered: false,
            submitReturned: false,
        };
        pendingRealTextFuture = future;
        stage = "receiver-slot";
        // [实验] #rs# 前缀时把接收方写入 SubmitAsync x2 槽（4.1.13 实测会 0x18 崩溃，默认关闭）
        if (content.indexOf('#rs#') === 0) {
            writeLibcxxString(state.add(0x50), receiver);
        }
        stage = "manager-provider";
        var manager = getRealTextManager();
        stage = "async-submit";
        nativeRealTextSubmitAsync(
            manager,
            payload,
            state.add(0x50),
            state.add(0x68),
            future);

        return new Promise(function (resolve) {
            var deadline = Date.now() + 3000;
            function waitForFactory() {
                if (realTextTraceFactoryTaskId !== 0) {
                    var nativeTaskId = realTextTraceFactoryTaskId;
                    realTextTraceActive = false;
                    console.log("[experimental-send] 异步文本任务已提交 taskId=" + nativeTaskId);
                    resolve("submitted:" + nativeTaskId);
                    return;
                }
                if (Date.now() >= deadline) {
                    realTextTraceActive = false;
                    clearPendingTextState();
                    resolve("fail: async text factory did not run");
                    return;
                }
                setTimeout(waitForFactory, 10);
            }
            waitForFactory();
        });
    } catch (error) {
        realTextTraceActive = false;
        clearPendingTextState();
        realTextLifecycleDiagnostics.failureStage = stage;
        realTextLifecycleDiagnostics.failureAddress = error.address ? error.address.toString() : "";
        if (stage === "manager-provider") {
            realTextSendReady = true;
            realTextSendStatus = "ready";
        } else {
            realTextSendReady = false;
            realTextSendStatus = "faulted";
        }
        return "fail: real text send fault at " + stage + ": " + error +
            " factory_entered=" + realTextTraceEnteredFactory +
            " factory_task_id=" + realTextTraceFactoryTaskId +
            " req2buf=" + realTextTraceReachedReq2Buf;
    } finally {
        if (payloadConstructed) {
            try { nativeRealTextPayloadDtor(payload); } catch (error) {
                console.error("[experimental-send] payload 析构失败: " + error);
            }
        }
    }
}

function getSendContextStatus() {
    // [4.1.13] 经典路径独立就绪判定：realText 故障不影响经典克隆发送
    if (classicTextSendReady && triggerX0 && lastRealX1Bytes && lastRealX1Addr) return "ready";
    if (realTextSendStatus === "faulted") return "faulted";
    if (!realTextAckHookReady) return "ack-unavailable";
    if (pendingBuf2RespTaskId !== 0) {
        if (pendingBuf2RespStartedAt !== 0 && Date.now() - pendingBuf2RespStartedAt > 20000) {
            clearPendingTextState();
        } else {
            return "busy";
        }
    }
    if (Date.now() < realTextReadyAfter) return "warming_up";
    if (!isRealTextManagerProviderReady()) return "warming_up";
    return realTextSendStatus;
}

function getReceiveContextStatus() {
    return JSON.stringify({
        status: receiverHookStatus,
        ready: receiverHookReady,
        attempts: receiverHookAttempts,
        error: receiverHookLastError,
    });
}

function getTextEncoderDiagnostics() {
    return JSON.stringify(realTextEncoderDiagnostics);
}

function getTextSendLifecycleDiagnostics() {
    return JSON.stringify(realTextLifecycleDiagnostics);
}

function cancelPendingTextMessage(taskId) {
    if (pendingBuf2RespTaskId === 0 || pendingBuf2RespTaskId !== Number(taskId)) return false;
    clearPendingTextState();
    return true;
}

function clearPendingTextState() {
    pendingBuf2RespTaskId = 0;
    pendingBuf2RespStartedAt = 0;
    pendingRealTextRequest = ptr(0);
    pendingSendMsgType = "";
    releasePendingRealTextFuture();
}

function AttachSendFunc() {
    var attempt = 0;
    function tryAttach() {
        try {
            doAttachSendFunc();
        } catch (e) {
            attempt += 1;
            console.log("[send-func] attach失败(第" + attempt + "次): " + e.message);
            if (attempt < 10) setTimeout(tryAttach, 1000);
        }
    }
    tryAttach();
}
function doAttachSendFunc() {
    Interceptor.attach(sendFuncAddr.add(0x10), {
        onEnter: function (args) {
            // 忽略本脚本主动发起的调用，只从微信自身的调用持续刷新 manager。
            if (triggeringStartTask) {
                return;
            }
            // X0 是长期存活的 STNManager；X1 使用 setup 中分配的自有缓冲区。
            // 每次正常 StartTask 都刷新 X0，避免微信内部重建管理器后继续使用旧地址。
            const currentX0 = this.context.x0;
            if (!isReadablePointer(currentX0)) {
                return;
            }
            const managerChanged = !triggerX0 || !currentX0.equals(triggerX0);
            triggerX0 = currentX0;
            if (managerChanged) {
                console.log(`[+] 捕获到有效 StartTask 调用，X0：${triggerX0}`);
            }
        }
    })
}


// -------------------------发送文本消息分区-------------------------


// -------------------------Req2Buf公共部分分区-------------------------
function attachReq2buf() {
    Interceptor.attach(req2bufEnterAddr, {
        onEnter: function (args) {
            if (!this.context.x1.equals(taskIdGlobal)) {
                return;
            }

            const x24_base = this.context.x24;
            insertMsgAddr = x24_base.add(0x60);

            if (sendMsgType === "text") {
                insertMsgAddr.writePointer(sendTextMessageAddr);
                console.log("[+] 发送文本消息成功! Req2Buf 已将 X24+0x60 指向新地址: " + sendTextMessageAddr +
                    "[+] Req2Buf 写入后内存预览: " + insertMsgAddr);
            } else if (sendMsgType === "img") {
                insertMsgAddr.writePointer(sendImgMessageAddr);
                console.log("[+] 发送图片消息成功! Req2Buf 已将 X24+0x60 指向新地址: " + sendImgMessageAddr +
                    "[+] Req2Buf 写入后内存预览: " + insertMsgAddr);
            } else if (sendMsgType === "video") {
                insertMsgAddr.writePointer(sendVideoMessageAddr);
                console.log("[+] 发送视频消息成功! Req2Buf 已将 X24+0x60 指向新地址: " + sendVideoMessageAddr +
                    "[+] Req2Buf 写入后内存预览: " + insertMsgAddr);
            } else if (sendMsgType === "reply") {
                insertMsgAddr.writePointer(sendReplyMessageAddr);
                console.log("[+] 发送回复消息成功! Req2Buf 已将 X24+0x60 指向新地址: " + sendReplyMessageAddr +
                    "[+] Req2Buf 写入后内存预览: " + insertMsgAddr);
            } else if (sendMsgType === "voice") {
                insertMsgAddr.writePointer(sendVoiceMessageAddr);
                console.log("[+] 发送语音消息成功! Req2Buf 已将 X24+0x60 指向新地址: " + sendVoiceMessageAddr +
                    "[+] Req2Buf 写入后内存预览: " + insertMsgAddr);
            } else if (sendMsgType === "file") {
                insertMsgAddr.writePointer(sendFileMessageAddr);
                console.log("[+] 发送文件消息成功! Req2Buf 已将 X24+0x60 指向新地址: " + sendFileMessageAddr +
                    "[+] Req2Buf 写入后内存预览: " + insertMsgAddr);
            } else if (sendMsgType === "fileupload") {
                insertMsgAddr.writePointer(sendFileUploadMessageAddr);
                console.log("[+] 发送fileUploadMsg成功! Req2Buf 已将 X24+0x60 指向新地址: " + sendFileUploadMessageAddr +
                    "[+] Req2Buf 写入后内存预览: " + insertMsgAddr);
			} else if (sendMsgType === "appattach") {
				insertMsgAddr.writePointer(sendAppAttachMessageAddr);
				console.log("[+] 发送uploadAppAttach成功! Req2Buf 已将 X24+0x60 指向新地址: " + sendAppAttachMessageAddr +
					"[+] Req2Buf 写入后内存预览: " + insertMsgAddr);
			} else if (sendMsgType === "mini_program") {
				insertMsgAddr.writePointer(sendFileMessageAddr);
				console.log("[+] 发送小程序卡片成功! Req2Buf 已将 X24+0x60 指向新地址: " + sendFileMessageAddr);
            }
        }
    });

    // 在出口处拦截req2buf，记录insertMsgAddr等buf2resp回调后再清理
    Interceptor.attach(req2bufExitAddr, {
        onEnter: function (args) {
            if (!this.context.x25.equals(taskIdGlobal)) {
                return;
            }
            // 不立即清除insertMsgAddr，让mars能路由buf2resp回调
            // 用fakeVtable保护结构体，防止中间被访问时崩溃
            if (sendMsgType === "mini_program") {
                miniProgramPendingInsertMsgAddr = insertMsgAddr;
                miniProgramPendingTaskId = taskIdGlobal;
            } else {
                pendingInsertMsgAddr = insertMsgAddr;
                pendingSendMsgType = sendMsgType;
                pendingBuf2RespTaskId = taskIdGlobal;
            }
            taskIdGlobal = 0;
        }
    });
}


// -------------------------Req2Buf公共部分分区-------------------------

// -------------------------发送图片消息分区-------------------------

// 初始化进行内存的分配
function setupSendImgMessageDynamic() {

    // 1. 动态分配内存块（按需分配大小）
    // 分配原则：字符串给 64-128 字节，结构体按实际大小分配
    imgCgiAddr = Memory.alloc(128);
    sendImgMessageAddr = Memory.alloc(256);
    imgMessageAddr = Memory.alloc(256);
    uploadFunc1Addr = Memory.alloc(24);
    uploadFunc2Addr = Memory.alloc(24);
    uploadCallback = Memory.alloc(128);
    imageIdAddr = Memory.alloc(256);
    md5Addr = Memory.alloc(256);
    uploadAesKeyAddr = Memory.alloc(256);
    ImagePathAddr1 = Memory.alloc(256);
    uploadImageX1 = Memory.alloc(1024);

    // 图片数据写入
    patchString(imgCgiAddr, "/cgi-bin/micromsg-bin/uploadmsgimg");

    sendImgMessageAddr.add(0x00).writeU64(0);
    sendImgMessageAddr.add(0x08).writeU64(0);
    sendImgMessageAddr.add(0x10).writeU64(0);
    sendImgMessageAddr.add(0x18).writeU64(1);
    sendImgMessageAddr.add(0x20).writeU32(taskIdGlobal);
    sendImgMessageAddr.add(0x28).writePointer(imgMessageAddr);

    imgMessageAddr.add(0x00).writePointer(fakeVtable);
    imgMessageAddr.add(0x08).writeU32(taskIdGlobal);
    imgMessageAddr.add(0x0c).writeU32(0x6e);
    imgMessageAddr.add(0x10).writeU64(0x3);
    imgMessageAddr.add(0x18).writePointer(imgCgiAddr);
    imgMessageAddr.add(0x20).writeU64(0x22);
    imgMessageAddr.add(0x28).writeU64(uint64("0x8000000000000030"));
    imgMessageAddr.add(0x30).writeU64(uint64("0x0000000001010100"));

    // 视频数据写入
    videoCgiAddr = Memory.alloc(128);
    sendVideoMessageAddr = Memory.alloc(256);
    videoMessageAddr = Memory.alloc(256);
    videoIdAddr = Memory.alloc(256);
    videoPathAddr1 = Memory.alloc(256);
    uploadVideoX1 = Memory.alloc(1024);

    patchString(videoCgiAddr, "/cgi-bin/micromsg-bin/uploadvideo");

    sendVideoMessageAddr.add(0x00).writeU64(0);
    sendVideoMessageAddr.add(0x08).writeU64(0);
    sendVideoMessageAddr.add(0x10).writeU64(0);
    sendVideoMessageAddr.add(0x18).writeU64(1);
    sendVideoMessageAddr.add(0x20).writeU32(taskIdGlobal);
    sendVideoMessageAddr.add(0x28).writePointer(videoMessageAddr);

    videoMessageAddr.add(0x00).writePointer(fakeVtable);
    videoMessageAddr.add(0x08).writeU32(taskIdGlobal);
    videoMessageAddr.add(0x0c).writeU32(0x6e);
    videoMessageAddr.add(0x10).writeU64(0x3);
    videoMessageAddr.add(0x18).writePointer(videoCgiAddr);
    videoMessageAddr.add(0x20).writeU64(0x21);
    videoMessageAddr.add(0x28).writeU64(uint64("0x8000000000000030"));
    videoMessageAddr.add(0x30).writeU64(uint64("0x0000000001010100"));

    // 语音数据写入
    voiceCgiAddr = Memory.alloc(128);
    sendVoiceMessageAddr = Memory.alloc(256);
    voiceMessageAddr = Memory.alloc(256);
    voiceIdAddr = Memory.alloc(256);
    voicePathAddr1 = Memory.alloc(256);
    uploadVoiceX1 = Memory.alloc(1024);
    voiceAudioDataAddr = Memory.alloc(5 * 1024 * 1024); // 预分配5MB

    patchString(voiceCgiAddr, "/cgi-bin/micromsg-bin/uploadvoice");

    sendVoiceMessageAddr.add(0x00).writeU64(0);
    sendVoiceMessageAddr.add(0x08).writeU64(0);
    sendVoiceMessageAddr.add(0x10).writeU64(0);
    sendVoiceMessageAddr.add(0x18).writeU64(1);
    sendVoiceMessageAddr.add(0x20).writeU32(taskIdGlobal);
    sendVoiceMessageAddr.add(0x28).writePointer(voiceMessageAddr);

    voiceMessageAddr.add(0x00).writePointer(fakeVtable);
    voiceMessageAddr.add(0x08).writeU32(taskIdGlobal);
    voiceMessageAddr.add(0x0c).writeU32(0x6e);
    voiceMessageAddr.add(0x10).writeU64(0x3);
    voiceMessageAddr.add(0x18).writePointer(voiceCgiAddr);
    voiceMessageAddr.add(0x20).writeU64(0x21);
    voiceMessageAddr.add(0x28).writeU64(uint64("0x8000000000000030"));
    voiceMessageAddr.add(0x30).writeU64(uint64("0x0000000001010100"));
}



function triggerSendMediaMessage(taskId, sender, receiver, protoHex, payloadHex, msgType) {
    if (!taskId || !receiver) {
        console.error("[!] " + msgType + ": taskId or receiver is empty!");
        return "fail";
    }

    const directSendAvailable = sendDirectFuncAddr && !sendDirectFuncAddr.isNull();
    if ((!directSendAvailable && !triggerX0) || !triggerX1Payload) {
        console.error("[!] triggerX0 或 triggerX1Payload 尚未初始化，请等待 hook 捕获");
        return "fail";
    }

    if (msgType === "text" && (textMessageAddr.isNull() || sendTextMessageAddr.isNull() || textCgiAddr.isNull())) {
        console.error("[!] 文本消息 Hook 尚未初始化，拒绝发送");
        return "fail: text hook unavailable";
    }

    if (!directSendAvailable && !isReadablePointer(triggerX0)) {
        console.error("[!] StartTask 上下文已失效，等待微信产生新的可写任务上下文");
        return "fail: stale start task context";
    }

    var msgAddrInfo = {
        "text":  { messageAddr: textMessageAddr,  sendMessageAddr: sendTextMessageAddr,  cgiAddr: textCgiAddr,  protoHexSetter: function(h) { textProtoHexGlobal = h; } },
        "img":   { messageAddr: imgMessageAddr,   sendMessageAddr: sendImgMessageAddr,   cgiAddr: imgCgiAddr,   protoHexSetter: function(h) { imgProtoHexGlobal = h; } },
        "video": { messageAddr: videoMessageAddr, sendMessageAddr: sendVideoMessageAddr, cgiAddr: videoCgiAddr, protoHexSetter: function(h) { videoProtoHexGlobal = h; } },
        "reply": { messageAddr: replyMessageAddr, sendMessageAddr: sendReplyMessageAddr, cgiAddr: replyCgiAddr, protoHexSetter: function(h) { replyProtoHexGlobal = h; } },
        "voice": { messageAddr: voiceMessageAddr, sendMessageAddr: sendVoiceMessageAddr, cgiAddr: voiceCgiAddr, protoHexSetter: function(h) { voiceProtoHexGlobal = h; } },
        "file":  { messageAddr: fileMessageAddr,  sendMessageAddr: sendFileMessageAddr,  cgiAddr: fileCgiAddr,  protoHexSetter: function(h) { fileProtoHexGlobal = h; } },
        "mini_program": { messageAddr: fileMessageAddr, sendMessageAddr: sendFileMessageAddr, cgiAddr: fileCgiAddr, protoHexSetter: function(h) { fileProtoHexGlobal = h; } },
        "fileupload": { messageAddr: fileUploadMessageAddr, sendMessageAddr: sendFileUploadMessageAddr, cgiAddr: fileUploadCgiAddr, protoHexSetter: function(h) { fileUploadProtoHexGlobal = h; } },
        "appattach": { messageAddr: appAttachMessageAddr, sendMessageAddr: sendAppAttachMessageAddr, cgiAddr: appAttachCgiAddr, protoHexSetter: function(h) { appAttachProtoHexGlobal = h; } },
    };

    var info = msgAddrInfo[msgType];
    if (!info) {
        console.error("[!] unknown msgType: " + msgType);
        return "fail";
    }

    info.protoHexSetter(protoHex);
    taskIdGlobal = taskId;

    info.messageAddr.add(0x08).writeU32(taskIdGlobal);
    info.sendMessageAddr.add(0x20).writeU32(taskIdGlobal);

    const payloadData = hexToByteArray(payloadHex);
    triggerX1Payload.writeByteArray(payloadData);
    triggerX1Payload.add(0x18).writePointer(info.cgiAddr);
    triggerX1Payload.add(0xb8).writePointer(triggerX1Payload.add(0xc0));
    triggerX1Payload.add(0x190).writePointer(triggerX1Payload.add(0x198));
    sendMsgType = msgType;

    const MMStartTask = directSendAvailable
        ? new NativeFunction(sendDirectFuncAddr, 'int64', ['pointer'])
        : new NativeFunction(sendFuncAddr, 'int64', ['pointer', 'pointer']);

    try {
        triggeringStartTask = true;
        if (directSendAvailable) {
            MMStartTask(triggerX1Payload);
        } else {
            MMStartTask(triggerX0, triggerX1Payload);
        }
        return "1";
    } catch (e) {
        console.error("[!] Error trigger " + msgType + " MMStartTask: " + e);
        return "fail";
    } finally {
        triggeringStartTask = false;
    }
}

function triggerSendImgMessage(taskId, sender, receiver, protoHex, payloadHex) {
    return triggerSendMediaMessage(taskId, sender, receiver, protoHex, payloadHex, "img");
}

function triggerSendVideoMessage(taskId, sender, receiver, protoHex, payloadHex) {
    return triggerSendMediaMessage(taskId, sender, receiver, protoHex, payloadHex, "video");
}


function triggerUploadImg(receiver, md5, imagePath, payloadHex) {
    return fillUploadX1AndStart(imageIdAddr, ImagePathAddr1, uploadImageX1, receiver, md5, imagePath, payloadHex);
}

function triggerUploadVideo(receiver, md5, videoPath, payloadHex) {
    return fillUploadX1AndStart(videoIdAddr, videoPathAddr1, uploadVideoX1, receiver, md5, videoPath, payloadHex);
}

function triggerUploadVoice(receiver, voicePath, payloadHex, audioDataHex, durationMs) {
    if (uploadGlobalX0.equals(ptr(0))) {
        console.error("[!] uploadGlobalX0 尚未初始化，请等待 hook 捕获");
        return "fail";
    }

    voiceDurationGlobal = durationMs;
    const payload = hexToByteArray(payloadHex);

    // 解码音频二进制数据，写入预分配的5MB内存
    const audioBytes = hexToByteArray(audioDataHex);
    const audioLen = audioBytes.length;
    voiceSilkDataLenGlobal = audioLen;
    voiceAudioDataAddr.writeByteArray(audioBytes);

    const voiceIdStr = receiver + "_" + String(Math.floor(Date.now() / 1000)) + "_" + Math.floor(Math.random() * 1001) + "_1";
    patchString(voiceIdAddr, voiceIdStr);
    patchString(voicePathAddr1, voicePath);

    uploadVoiceX1.writeByteArray(payload);
    uploadVoiceX1.writePointer(uploadFunc1Addr);
    uploadVoiceX1.add(0x08).writePointer(uploadFunc2Addr);
    uploadVoiceX1.add(0x48).writePointer(voiceIdAddr);
    uploadVoiceX1.add(0x50).writeU64(voiceIdStr.length);
    uploadVoiceX1.add(0x58).writeU64(uint64("0x8000000000000000").add(voiceIdStr.length + 1));
    uploadVoiceX1.add(0x68).writeUtf8String(receiver);
    // 音频二进制数据: 0x100=指针, 0x108=长度, 0x110=容量(长度+1)|高位
    uploadVoiceX1.add(0x100).writePointer(voiceAudioDataAddr);
    uploadVoiceX1.add(0x108).writeU64(audioLen);
    uploadVoiceX1.add(0x110).writeU64(uint64("0x8000000000000000").add(audioLen + 1));

    const startUploadMedia = new NativeFunction(uploadImageAddr, 'int64', ['pointer', 'pointer']);

    return startUploadMedia(uploadGlobalX0, uploadVoiceX1);
}

function attachUploadMedia() {
    Interceptor.attach(uploadImageAddr.add(0x10), {
        onEnter: function (args) {
			uploadGlobalX0 = this.context.x0;
		}
    })
}



function patchCdnOnComplete() {
    Interceptor.attach(cndOnCompleteAddr, {
        onEnter: function (args) {

            try {
                const x2 = this.context.x2;
                const currentFileId = x2.add(0x20).readPointer().readUtf8String();
                const imageFileId = imageIdAddr.readUtf8String();
                const videoFileId = videoIdAddr.readUtf8String();
                const voiceFileId = voiceIdAddr.readUtf8String();
                const fileUploadFileId = uploadFileIdAddr.readUtf8String();
                if (currentFileId !== imageFileId && currentFileId !== videoFileId && currentFileId !== voiceFileId && currentFileId !== fileUploadFileId) {
                    console.log("[-] CndOnComplete x2: " + x2 + " currentFileId: " + currentFileId +
                        " imageFileId: " + imageFileId + " videoFileId:" + videoFileId + " voiceFileId:" + voiceFileId + " fileUploadFileId:" + fileUploadFileId);
                    return;
                }

                const cdnKey = x2.add(0x60).readPointer().readUtf8String();
                const aesKey = x2.add(0x78).readPointer().readUtf8String();
                const md5Key = x2.add(0x90).readPointer().readUtf8String();
                const videoId = x2.add(0xf0).readPointer().readUtf8String();
                const targetId = x2.add(0x40).readUtf8String();

                console.log("cndOnComplete x2: " + x2 + " cdnKey: " + cdnKey + " aesKey: " + aesKey + " md5Key: " + md5Key + " videoId: " + videoId + " targetId: " + targetId);

                if (cdnKey !== "" && cdnKey != null && aesKey !== "" && aesKey != null) {

                    // 判断是语音、视频、文件还是图片
                    if (currentFileId === voiceFileId) {
                        // 语音
                        send({
                            type: "upload_voice_finish",
                            target_id: targetId,
                            cdn_key: cdnKey,
                            aes_key: aesKey,
                            voice_duration: voiceDurationGlobal,
                            silk_data_len: voiceSilkDataLenGlobal
                        });
                    } else if (currentFileId === fileUploadFileId) {
                        // 文件
                        var attachId = "@cdn_" + cdnKey + "_" + aesKey + "_1";
                        send({
                            type: "upload_file_finish",
                            target_id: targetId,
                            cdn_key: cdnKey,
                            aes_key: aesKey,
                            md5_key: md5Key,
                            attach_id: attachId,
                            file_upload_token: "",
                            overwrite_msg_id: ""
                        });
                    } else if (currentFileId === videoFileId) {
                        // 视频
                        send({
                            type: "upload_video_finish",
                            target_id: targetId,
                            cdn_key: cdnKey,
                            aes_key: aesKey,
                            md5_key: md5Key,
                            video_id: videoId
                        });
                    } else {
                        // 图片
                        send({
                            type: "upload_image_finish",
                            target_id: targetId,
                            cdn_key: cdnKey,
                            aes_key: aesKey,
                            md5_key: md5Key
                        });
                    }
                } else {
                    console.error("cdnKey or aesKey 为空");
                }
            } catch (e) {
                console.error("[-] CdnOnComplete error: " + e);
            }
        }
    });
}


function attachGetCallbackFromWrapper() {
    Interceptor.attach(uploadGetCallbackWrapperAddr, {
        onEnter: function (args) {
            try {
                const tmpFileId = this.context.x1.readPointer().readUtf8String();
                const imageFileId = imageIdAddr.readUtf8String();
                const videoFileId = videoIdAddr.readUtf8String();
                const voiceFileId = voiceIdAddr.readUtf8String();
                const fileUploadFileId = uploadFileIdAddr.readUtf8String();
                if (tmpFileId !== imageFileId && tmpFileId !== videoFileId && tmpFileId !== voiceFileId && tmpFileId !== fileUploadFileId) {
                    console.log("[+] GetCallbackFromWrapper tmpFileId: " + tmpFileId + " imageFileId: " + imageFileId + " videoFileId:" + videoFileId + " voiceFileId:" + voiceFileId + " fileUploadFileId:" + fileUploadFileId);
                    return
                }

                uploadCallback.add(0x10).writePointer(uploadGetCallbackWrapperFuncAddr);
                this.context.x8 = uploadCallback;
            } catch (e) {
                console.error("[-] GetCallbackFromWrapper error: " + e);
            }
        }
    })

    Interceptor.attach(uploadOnCompleteAddr, {
        onEnter: function (args) {
            try {
                const tmpFileId = this.context.x1.readPointer().readUtf8String();
                const imageFileId = imageIdAddr.readUtf8String();
                const videoFileId = videoIdAddr.readUtf8String();
                const voiceFileId = voiceIdAddr.readUtf8String();
                const fileUploadFileId = uploadFileIdAddr.readUtf8String();
                if (tmpFileId !== imageFileId && tmpFileId !== videoFileId && tmpFileId !== voiceFileId && tmpFileId !== fileUploadFileId) {
                    console.log("[+] OnComplete tmpFileId: " + tmpFileId + " imageFileId: " + imageFileId + " videoFileId:" + videoFileId + " voiceFileId:" + voiceFileId + " fileUploadFileId:" + fileUploadFileId);
                    return
                }

                uploadCallback.add(0x30).writePointer(uploadOnCompleteFuncAddr);
                this.context.x8 = uploadCallback;
            } catch (e) {
                console.error("[-] OnComplete error: " + e);
            }
        }
    })
}


// -------------------------发送回复消息分区-------------------------
function setupSendReplyMessageDynamic() {
    replyCgiAddr = Memory.alloc(128);
    sendReplyMessageAddr = Memory.alloc(256);
    replyMessageAddr = Memory.alloc(256);

    patchString(replyCgiAddr, "/cgi-bin/micromsg-bin/sendappmsg");

    sendReplyMessageAddr.add(0x00).writeU64(0);
    sendReplyMessageAddr.add(0x08).writeU64(0);
    sendReplyMessageAddr.add(0x10).writeU64(0);
    sendReplyMessageAddr.add(0x18).writeU64(1);
    sendReplyMessageAddr.add(0x20).writeU32(taskIdGlobal);
    sendReplyMessageAddr.add(0x28).writePointer(replyMessageAddr);

    replyMessageAddr.add(0x00).writePointer(fakeVtable);
    replyMessageAddr.add(0x08).writeU32(taskIdGlobal);
    replyMessageAddr.add(0x0c).writeU32(0x6e);
    replyMessageAddr.add(0x10).writeU64(0x3);
    replyMessageAddr.add(0x18).writePointer(replyCgiAddr);
    replyMessageAddr.add(0x20).writeU64(0x20);
    replyMessageAddr.add(0x28).writeU64(uint64("0x8000000000000030"));
    replyMessageAddr.add(0x30).writeU64(uint64("0x0000000001010100"));

    console.log("[+] Reply message setup complete. CgiAddr: " + replyCgiAddr + " SendAddr: " + sendReplyMessageAddr);
}


function triggerSendReplyMessage(taskId, sender, receiver, protoHex, payloadHex) {
    return triggerSendMediaMessage(taskId, sender, receiver, protoHex, payloadHex, "reply");
}

// -------------------------发送回复消息分区-------------------------

// -------------------------发送语音消息分区-------------------------
function triggerSendVoiceMessage(taskId, sender, receiver, protoHex, payloadHex) {
    return triggerSendMediaMessage(taskId, sender, receiver, protoHex, payloadHex, "voice");
}
// -------------------------发送语音消息分区-------------------------

rpc.exports = {
    getSendContextStatus: getSendContextStatus,
    getReceiveContextStatus: getReceiveContextStatus,
    getTextEncoderDiagnostics: getTextEncoderDiagnostics,
    getTextSendLifecycleDiagnostics: getTextSendLifecycleDiagnostics,
    cancelPendingTextMessage: cancelPendingTextMessage,
    getMiniProgramSendStatus: getMiniProgramSendStatus,
    cancelPendingMiniProgram: cancelPendingMiniProgram,
    triggerSendImgMessage: triggerSendImgMessage,
    triggerUploadImg: triggerUploadImg,
    triggerSendTextMessage: triggerSendTextMessage,
    triggerDownload: triggerDownload,
    triggerUploadVideo: triggerUploadVideo,
    triggerSendVideoMessage: triggerSendVideoMessage,
    triggerSendReplyMessage: triggerSendReplyMessage,
    triggerUploadVoice: triggerUploadVoice,
    triggerSendVoiceMessage: triggerSendVoiceMessage,
    triggerSendFileMessage: triggerSendFileMessage,
    triggerSendMiniProgram: triggerSendMiniProgram,
    triggerSendFileUploadMessage: triggerSendFileUploadMessage,
    triggerUploadFile: triggerUploadFile,
    triggerUploadAppAttach: triggerUploadAppAttach,
};

// -------------------------发送图片消息分区-------------------------

// -------------------------接收消息分区-------------------------
function setupDownloadFileDynamic() {
    downloadFileX1 = Memory.alloc(1624)
    fileIdAddr = Memory.alloc(128)
    downloadAesKeyAddr = Memory.alloc(128)
    filePathAddr = Memory.alloc(256)
    fileCdnUrlAddr = Memory.alloc(256)

}


function setupReceiverWithRetry() {
    function attempt() {
        if (receiverHookReady) return;
        receiverHookAttempts++;
        try {
            setReceiver();
            receiverHookReady = true;
            receiverHookStatus = "ready";
            receiverHookLastError = "";
            console.log("[+] 消息接收 Hook 已启用，attempt=" + receiverHookAttempts);
        } catch (error) {
            receiverHookLastError = String(error);
            if (receiverHookAttempts >= 20) {
                receiverHookStatus = "faulted";
                console.error("[receive-hook] 初始化失败，已停止重试: " + error);
                return;
            }
            receiverHookStatus = "initializing";
            console.warn("[receive-hook] 初始化失败，500ms 后重试 attempt=" + receiverHookAttempts + ": " + error);
            setTimeout(attempt, 500);
        }
    }
    setTimeout(attempt, 500);
}

function setReceiver() {
	// 4.1.13 的响应点位于 AutoBuffer vtable 调用之后；旧版本仍使用 x0=长度、x1=数据指针。
	var respHookAddr = receiveResponseAddr;
	var recvStats = { n: 0, window: Date.now(), rate: 0 };
	var handler = {
		onEnter: function (args) {
			// 热路径性能保护：先做最廉价的长度检查和单字节预检，非消息载荷零成本返回
			recvStats.n += 1;
			var now = Date.now();
			if (now - recvStats.window > 30000) {
				recvStats.rate = Math.round(recvStats.n * 30000 / (now - recvStats.window));
				console.log('[recv-rate] 30s 内 ' + recvStats.n + ' 次 (~' + recvStats.rate + '/s)');
				recvStats.n = 0;
				recvStats.window = now;
			}
			var currentPtr = null;
			var x2 = 0;
			if (receiveResponseMode === "auto_buffer") {
				// Hook 位于 `add x0, sp, #0x50` 之前，AutoBuffer 仍在调用方栈上。
				var response = readReceiveAutoBuffer(this.context.sp.add(0x50));
				if (!response) return;
				currentPtr = response.data;
				x2 = response.length;
			} else {
				currentPtr = this.context.x1;
				x2 = this.context.x0.toInt32();
			}
			if (x2 < 4 || x2 > MAX_FRIDA_MESSAGE_BYTES) {
				return;
			}
			if (receiveResponseMode !== "auto_buffer" && !isReadablePointer(currentPtr)) {
				return;
			}
			// [diag] 头部采样：小载荷记录前8字节判断数据形态（加密 or protobuf变体）
			try {
				var firstByte = receiveResponseMode === "auto_buffer" ? new Uint8Array(currentPtr)[0] : currentPtr.readU8();
				if (recvStats.samples === undefined) recvStats.samples = 0;
				if (recvStats.samples < 20 && x2 < 2048) {
					recvStats.samples += 1;
					var head8 = receiveResponseMode === "auto_buffer"
						? Array.from(new Uint8Array(currentPtr).slice(0, Math.min(8, x2))).map(function (b) { return b.toString(16).padStart(2, '0') }).join(' ')
						: Array.from(new Uint8Array(currentPtr.readByteArray(Math.min(8, x2)))).map(function (b) { return b.toString(16).padStart(2, '0') }).join(' ');
					console.log('[recv-sample ' + recvStats.samples + '] len=' + x2 + ' head=' + head8);
				}
				if (receiveResponseMode !== "auto_buffer" && firstByte !== 0x08) {
					return;
				}
			} catch (e) {
				return;
			}
			// taskId 读取有风险（帧布局版本相关），小程序/克隆文本分支需要时才读
			var respTaskId = 0;
			if (miniProgramPendingTaskId !== 0 || classicPendingTaskId !== 0) {
				try {
					respTaskId = this.context.sp.add(0x140).readS32();
				} catch (e) {
					respTaskId = 0;
				}
			}

			// [classic-send] 克隆文本任务 ACK：真实响应字节交给 Go 解析 ret（不伪造成功）
			if (classicPendingTaskId !== 0 && respTaskId === classicPendingTaskId) {
				var ackBytes = receiveResponseMode === "auto_buffer"
					? Array.from(new Uint8Array(currentPtr.readByteArray(x2)))
					: Array.from(new Uint8Array(readByteArrayIfReadable(currentPtr, x2) || new Uint8Array(0)));
				classicPendingTaskId = 0;
				console.log("[classic-ack] 收到克隆任务 ACK taskId=" + respTaskId + " len=" + ackBytes.length);
				send({ type: "buf2resp", msg_type: "text", data: ackBytes });
				return;
			}

            if (miniProgramPendingTaskId !== 0 && respTaskId === miniProgramPendingTaskId) {
                if (!miniProgramPendingInsertMsgAddr.isNull()) {
                    miniProgramPendingInsertMsgAddr.writeU64(0);
                    miniProgramPendingInsertMsgAddr = ptr(0);
                }
				var response = receiveResponseMode === "auto_buffer" ? currentPtr : readByteArrayIfReadable(currentPtr, x2);
                send({
                    type: "buf2resp",
                    msg_type: "mini_program",
                    data: response ? Array.from(new Uint8Array(response)) : [],
                });
                console.log("[mini-program-send] 收到卡片 ACK taskId=" + respTaskId + " len=" + x2);
                miniProgramPendingTaskId = 0;
                return;
            }

			const mem = receiveResponseMode === "auto_buffer" ? currentPtr : readByteArrayIfReadable(currentPtr, x2);
            if (!mem) {
                console.warn("[skip] protobuf_msg memory read failed, length=" + x2);
                return;
            }
            const uint8Array = new Uint8Array(mem);
            // 与已验证稳定的旧版本保持一致，只做最宽松的消息候选判断。
            // 具体结构交给 Go 解析，宁可产生误判日志，也不要在 JS 层漏掉消息。
			if (receiveResponseMode !== "auto_buffer" && uint8Array[0] !== 0x08) {
                return;
            }

            send({
                type: "protobuf_msg",
                data: Array.from(uint8Array),
            })
		},
	};
	try {
		Interceptor.attach(respHookAddr, handler);
	} catch (e) {
		throw new Error("响应投递点 attach 失败: " + e.message);
	}
		console.log("[receive] 响应投递点已挂载 @" + receiveResponseAddr + " mode=" + receiveResponseMode);
}

function attachMediaDownloadHooks() {
    Interceptor.attach(startDownloadMedia, {
        onEnter: function (args) {
            downloadGlobalX0 = this.context.x0;
            var fileIDAddr = readPointerIfReadable(this.context.x1.add(0x40));
            var fileId = readUtf8StringIfReadable(fileIDAddr);
            if (!fileId || !isReadablePointer(this.context.x1.add(0xA0))) {
                return;
            }
            const t = this.context.x1.add(0xA0).readU32()
            if (t === 3) {
                if (fileId.endsWith("_1")) {
                    this.context.x1.add(0xA0).writeU32(0x02);
                }
                if (fileId.endsWith("_31")) {
                    this.context.x1.add(0xA0).writeU32(0x04);
                }
            }
        }
    })

    Interceptor.attach(downloadFileAddr, {
        onEnter: function (args) {
			var dataPtr = this.context.x22;
			var dataLen = this.context.x2.toInt32();
			var fileId = readUtf8StringIfReadable(readPointerIfReadable(this.context.x19.add(0x2E0)));
			var cdnUrl = readUtf8StringIfReadable(readPointerIfReadable(this.context.x19.add(0x2F8)));

            sendDownloadChunks(dataPtr, dataLen, fileId, cdnUrl);
        }
    });

    Interceptor.attach(downloadImagAddr, {
        onEnter: function (args) {
            var dataPtr = this.context.x22;
            var dataLen = this.context.x2.toInt32();
            var fileId = readUtf8StringIfReadable(readPointerIfReadable(this.context.x19.add(0x2E0)));
            var cdnUrl = readUtf8StringIfReadable(readPointerIfReadable(this.context.x19.add(0x2F8)));

            sendDownloadChunks(dataPtr, dataLen, fileId, cdnUrl);
        }
    });

    Interceptor.attach(downloadVideoAddr, {
        onEnter: function (args) {
			var dataPtr = readPointerIfReadable(this.context.x20.add(0x178));
			var dataLen = this.context.x23.toInt32();
			var fileId = readUtf8StringIfReadable(readPointerIfReadable(this.context.x19.add(0x2E0)));
			var cdnUrl = readUtf8StringIfReadable(readPointerIfReadable(this.context.x19.add(0x2F8)));

            sendDownloadChunks(dataPtr, dataLen, fileId, cdnUrl);
        }
    });
	console.log("[experimental] 媒体下载 Hook 已启用");
}


// fileType:  HdImage => 1,Image => 2, thumbImage => 3, Video => 4, File => 5,
function triggerDownload(receiver, cdnUrl, aesKey, filePath, fileType) {
    if (!downloadGlobalX0) {
        console.error("[!] downloadGlobalX0 尚未初始化，请等待 hook 捕获");
        return "fail";
    }

    const downloadMediaPayload = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x00
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x10
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x20
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x30
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xF0, 0xB6, 0x4C, 0xFC, 0x0A, 0x00, 0x00, 0x00, // 0x40
        0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
        0x80, 0x10, 0x4B, 0xFA, 0x0A, 0x00, 0x00, 0x00, // 0x58
        0xB2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
        0xF0, 0xB3, 0x4C, 0xFC, 0x0A, 0x00, 0x00, 0x00, // 0x70
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
        0x60, 0xC4, 0x2D, 0xFE, 0x0A, 0x00, 0x00, 0x00, // 0x88
        0xC8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x90
        0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // 0x98
        0x03, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, // 0xa0
        0x00, 0x00, 0x00, 0x00, 0x01, 0xAA, 0xAA, 0xAA, // 0xa8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xb0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xc0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xd0
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xd8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xe0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xf0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x100
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x110
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, // 0x128
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x11, 0x28, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x148
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x00, 0xAA, 0xAA, 0xAA, // 0x170
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, // 0x180
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x1E, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, // 0x1a0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x22, 0x1A, 0xFE, 0x0A, 0x00, 0x00, 0x00, // 0x1d0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x1f0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x200
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x288
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x298
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x2a0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x00, 0x4F, 0x56, 0xFC, 0x0A, 0x00, 0x00, 0x00, // 0x2c0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x300
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, // 0x318
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x340
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, // 0x378
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x80, 0x3F, 0x00, 0x00, 0x00, 0x00, // 0x3e0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    patchString(fileIdAddr, receiver + "_" + String(Math.floor(Date.now() / 1000)) + "_" + Math.floor(Math.random() * 1001) + "_1");
    patchString(fileCdnUrlAddr, cdnUrl)
    patchString(downloadAesKeyAddr, aesKey)
    patchString(filePathAddr, filePath);

    downloadFileX1.writeByteArray(downloadMediaPayload);
    downloadFileX1.add(0x40).writePointer(fileIdAddr);
    downloadFileX1.add(0x58).writePointer(fileCdnUrlAddr);
    downloadFileX1.add(0x70).writePointer(downloadAesKeyAddr);
    downloadFileX1.add(0x88).writePointer(filePathAddr);
    downloadFileX1.add(0xa0).writeU32(fileType);

    const startDwMedia = new NativeFunction(startDownloadMedia, 'int64', ['pointer', 'pointer']);
    return startDwMedia(downloadGlobalX0, downloadFileX1);
}

// -------------------------接收消息分区-------------------------
