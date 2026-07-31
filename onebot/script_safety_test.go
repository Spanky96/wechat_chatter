package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"text/template"
)

func renderFridaScript(t *testing.T, configPath string, enableUnsafeSend bool) string {
	t.Helper()
	configData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var values map[string]any
	if err := json.Unmarshal(configData, &values); err != nil {
		t.Fatal(err)
	}
	values["EnableUnsafeSend"] = enableUnsafeSend
	values["EnableMediaHooks"] = false
	values["EnableMediaDownloadHooks"] = false

	source, err := os.ReadFile("script.js")
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err := template.New("fridaScript").Parse(string(source))
	if err != nil {
		t.Fatal(err)
	}
	var rendered bytes.Buffer
	if err := tmpl.Execute(&rendered, values); err != nil {
		t.Fatal(err)
	}
	return rendered.String()
}

func TestReceiveOnlyTemplateOmitsUnsafeHooks(t *testing.T) {
	code := renderFridaScript(t, "../wechat_version/4_1_11_53_mac.json", false)
	if !strings.Contains(code, `scheduleHookSetup("消息接收", setReceiver)`) {
		t.Fatal("receive hook is missing")
	}
	for _, unsafeSetup := range []string{
		`scheduleHookSetup("文本消息内存"`,
		`scheduleHookSetup("文本消息编码"`,
		`scheduleHookSetup("StartTask"`,
		`scheduleHookSetup("Req2Buf"`,
		`scheduleHookSetup("媒体下载"`,
	} {
		if strings.Contains(code, unsafeSetup) {
			t.Fatalf("unsafe hook remains in receive-only script: %s", unsafeSetup)
		}
	}
}

func TestExperimentalTextTemplateUsesRealFactoryOnly(t *testing.T) {
	code := renderFridaScript(t, "../wechat_version/4_1_11_53_mac.json", true)
	if !strings.Contains(code, `scheduleHookSetup("真实工厂文本发送", setupRealTextSend)`) {
		t.Fatal("real factory sender is missing")
	}
	if !strings.Contains(code, `!realTextSendReady || !realTextAckHookReady`) {
		t.Fatal("experimental sender is not gated on the ACK hook")
	}
	if strings.Contains(code, `if (!realTextSendReady || !realTextAckHookReady || !receiverHookReady)`) {
		t.Fatal("experimental sender is incorrectly coupled to the legacy receive hook")
	}
	if !strings.Contains(code, `Interceptor.attach(realTextResponseAddr`) {
		t.Fatal("text response entry hook is missing")
	}
	if !strings.Contains(code, `Interceptor.attach(realTextEncoderAddr`) {
		t.Fatal("text encoder entry diagnostic is missing")
	}
	if !strings.Contains(code, `summarizeProtoShape(new Uint8Array(encoded.data), 0)`) {
		t.Fatal("text encoder diagnostic does not redact payload values")
	}
	if !strings.Contains(code, `getTextEncoderDiagnostics: getTextEncoderDiagnostics`) {
		t.Fatal("text encoder diagnostics are not exposed for controlled comparison")
	}
	if !strings.Contains(code, `getTextSendLifecycleDiagnostics: getTextSendLifecycleDiagnostics`) {
		t.Fatal("text send lifecycle diagnostics are not exposed")
	}
	if !strings.Contains(code, `cancelPendingTextMessage: cancelPendingTextMessage`) {
		t.Fatal("timed out text sends cannot clear their pending state")
	}
	if !strings.Contains(code, `Interceptor.attach(realTextReq2BufAddr`) {
		t.Fatal("Req2Buf entry diagnostic is missing")
	}
	if !strings.Contains(code, `realTextTraceReq2BufTaskIds.indexOf(realTextTraceFactoryTaskId)`) {
		t.Fatal("Req2Buf diagnostic does not handle entry before the factory returns")
	}
	if !strings.Contains(code, `submissionPath: "async-no-wait"`) {
		t.Fatal("text sender still uses the synchronous future-wait path")
	}
	if !strings.Contains(code, `nativeRealTextSubmitAsync(`) {
		t.Fatal("direct async text submission is missing")
	}
	if !strings.Contains(code, `['pointer', 'pointer', 'pointer']`) {
		t.Fatal("async submission does not declare the ARM64 indirect-result ABI")
	}
	if strings.Contains(code, `nativeRealTextSendAsync(state)`) {
		t.Fatal("synchronous future-wait wrapper remains active")
	}
	if !strings.Contains(code, `releasePendingRealTextFuture();`) {
		t.Fatal("async future lifecycle is not released")
	}
	if !strings.Contains(code, `readRealTextAutoBuffer(autoBuffer)`) {
		t.Fatal("ACK bytes are not read through the native AutoBuffer API")
	}
	if !strings.Contains(code, `if (!isRealTextManagerProviderReady()) return "warming_up"`) {
		t.Fatal("send readiness ignores the native manager provider lifecycle")
	}
	if !strings.Contains(code, `realTextReadyAfter = Date.now() + 15000`) {
		t.Fatal("send readiness lacks a cold-start stabilization window")
	}
	for _, legacySetup := range []string{
		`setupRetOneStub();`,
		`scheduleHookSetup("文本消息编码"`,
		`scheduleHookSetup("StartTask"`,
		`scheduleHookSetup("Req2Buf"`,
	} {
		if strings.Contains(code, legacySetup) {
			t.Fatalf("legacy unsafe sender is active: %s", legacySetup)
		}
	}
}

func TestSupportedVersionTemplatesHaveValidJavaScript(t *testing.T) {
	nodePath, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is unavailable")
	}
	configPaths, err := filepath.Glob("../wechat_version/*.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, configPath := range configPaths {
		configPath := configPath
		t.Run(filepath.Base(configPath), func(t *testing.T) {
			configData, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			var values map[string]any
			if err := json.Unmarshal(configData, &values); err != nil {
				t.Fatal(err)
			}
			for _, requiredKey := range []string{
				"blrX8Addr", "autoBufferWriteFunc", "req2bufEnterAddr", "req2bufExitAddr",
				"sendFuncAddr", "buf2RespAddr", "uploadImageAddr", "cndOnCompleteAddr",
				"uploadGetCallbackWrapperAddr", "uploadGetCallbackWrapperFuncAddr",
				"uploadOnCompleteAddr", "uploadOnCompleteFuncAddr", "downloadImagAddr",
				"startDownloadMedia", "downloadFileAddr", "downloadVideoAddr",
			} {
				if values[requiredKey] == nil {
					t.Skipf("legacy config does not provide %s", requiredKey)
				}
			}
			code := renderFridaScript(t, configPath, false)
			tempPath := filepath.Join(t.TempDir(), "script.js")
			if err := os.WriteFile(tempPath, []byte(code), 0o600); err != nil {
				t.Fatal(err)
			}
			if output, err := exec.Command(nodePath, "--check", tempPath).CombinedOutput(); err != nil {
				t.Fatalf("invalid rendered JavaScript: %v\n%s", err, output)
			}
		})
	}
}
