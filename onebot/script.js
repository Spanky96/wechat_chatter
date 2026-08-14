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
    scheduleHookSetup("真实工厂文本发送", setupRealTextSend);
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
        console.error("[hook-disabled] " + name + " 初始化失败: " + error + " stack=" + (error.stack || ""));
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
var miniProgramPendingTaskId = 0;
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
    // Three pointer-sized fields force ARM64's indirect-result ABI (x8). The actual
    // C++ future occupies the first two fields; the third is only ABI padding here.
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

function setupRealTextSend() {
    var requiredAddresses = [
        realTextSubmitAsyncAddr,
        realTextManagerProviderAddr,
        realTextSendFactoryAddr,
        realTextRequestCtorAddr,
        realTextEncoderAddr,
        realTextResponseAddr,
        realTextReq2BufAddr,
        realTextAutoBufferDataAddr,
        realTextAutoBufferLengthAddr,
        realTextPayloadCtorAddr,
        realTextParseFromArrayAddr,
        realTextPayloadDtorAddr,
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
    nativeRealTextPayloadDtor = new NativeFunction(realTextPayloadDtorAddr, 'void', ['pointer']);
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
            pendingBuf2RespTaskId = 0;
            pendingRealTextRequest = ptr(0);
            pendingSendMsgType = "";
            releasePendingRealTextFuture();
            if (!responseBytes) {
                console.error("[experimental-send] 文本 ACK 读取失败 taskId=" + responseTaskId);
                send({ type: "buf2resp", msg_type: msgType, data: [] });
                return;
            }

            var bytes = new Uint8Array(responseBytes);
            console.log("[experimental-send] 收到文本 ACK taskId=" + responseTaskId + " len=" + bytes.length);
            send({ type: "buf2resp", msg_type: msgType, data: Array.from(bytes) });
        },
    });
    Interceptor.attach(realTextReq2BufAddr, {
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

function triggerSendTextMessage(taskId, receiver, content, atUser, protoHex, payloadHex) {
    if (!realTextSendReady || !realTextAckHookReady) {
        return "fail: real text sender or ACK hook unavailable";
    }
    if (!protoHex || protoHex.length === 0 || (protoHex.length % 2) !== 0) {
        return "fail: invalid text protobuf";
    }
    if (pendingBuf2RespTaskId !== 0) return "fail: another send is awaiting ack";

    var protoBytes = hexToByteArray(protoHex);
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
                    pendingBuf2RespTaskId = 0;
                    pendingRealTextRequest = ptr(0);
                    pendingSendMsgType = "";
                    releasePendingRealTextFuture();
                    resolve("fail: async text factory did not run");
                    return;
                }
                setTimeout(waitForFactory, 10);
            }
            waitForFactory();
        });
    } catch (error) {
        realTextTraceActive = false;
        pendingBuf2RespTaskId = 0;
        pendingRealTextRequest = ptr(0);
        pendingSendMsgType = "";
        releasePendingRealTextFuture();
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
    if (realTextSendStatus === "faulted") return "faulted";
    if (!realTextAckHookReady) return "ack-unavailable";
    if (pendingBuf2RespTaskId !== 0) return "busy";
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
    pendingBuf2RespTaskId = 0;
    pendingRealTextRequest = ptr(0);
    pendingSendMsgType = "";
    releasePendingRealTextFuture();
    return true;
}

function AttachSendFunc() {
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
	Interceptor.attach(buf2RespAddr, {
		onEnter: function (args) {
			var respTaskId = this.context.sp.add(0x140).readS32();
				const currentPtr = this.context.x20;
				const x2 = this.context.x0.toInt32();
	            if (!isReadablePointer(currentPtr) || x2 < 4 || x2 > MAX_FRIDA_MESSAGE_BYTES) {
					return;
	            }

            if (miniProgramPendingTaskId !== 0 && respTaskId === miniProgramPendingTaskId) {
                if (!miniProgramPendingInsertMsgAddr.isNull()) {
                    miniProgramPendingInsertMsgAddr.writeU64(0);
                    miniProgramPendingInsertMsgAddr = ptr(0);
                }
                var response = readByteArrayIfReadable(currentPtr, x2);
                send({
                    type: "buf2resp",
                    msg_type: "mini_program",
                    data: response ? Array.from(new Uint8Array(response)) : [],
                });
                console.log("[mini-program-send] 收到卡片 ACK taskId=" + respTaskId + " len=" + x2);
                miniProgramPendingTaskId = 0;
                return;
            }

            const mem = readByteArrayIfReadable(currentPtr, x2);
            if (!mem) {
                console.warn("[skip] protobuf_msg memory read failed, length=" + x2);
                return;
            }
            const uint8Array = new Uint8Array(mem);
            // 与已验证稳定的旧版本保持一致，只做最宽松的消息候选判断。
            // 具体结构交给 Go 解析，宁可产生误判日志，也不要在 JS 层漏掉消息。
            if (uint8Array[0] !== 0x08) {
                return;
            }

            send({
                type: "protobuf_msg",
                data: Array.from(uint8Array),
            })
		},
	});
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
