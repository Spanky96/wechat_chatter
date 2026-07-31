package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSendStatusReportsCrashProtection(t *testing.T) {
	previous := config.EnableUnsafeSend
	config.EnableUnsafeSend = false
	t.Cleanup(func() { config.EnableUnsafeSend = previous })

	recorder := httptest.NewRecorder()
	sendStatusHandler(recorder, httptest.NewRequest(http.MethodGet, "/send_status", nil))

	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["ready"] != false || body["status"] != "disabled" || body["reason"] == "" {
		t.Fatalf("unexpected status response: %#v", body)
	}
}

func TestSendHandlerRejectsBeforeQueueing(t *testing.T) {
	previous := config.EnableUnsafeSend
	config.EnableUnsafeSend = false
	t.Cleanup(func() { config.EnableUnsafeSend = previous })

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/send_group_msg", strings.NewReader(`{"group_id":"room@chatroom","message":[{"type":"text","data":{"text":"test"}}]}`))
	sendHandler(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestExperimentalSendRejectsMediaBeforeQueueing(t *testing.T) {
	previous := config.EnableUnsafeSend
	config.EnableUnsafeSend = true
	t.Cleanup(func() { config.EnableUnsafeSend = previous })

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/send_group_msg", strings.NewReader(`{"group_id":"room@chatroom","message":[{"type":"image","data":{"file":"base64://test"}}]}`))
	sendHandler(recorder, request)

	if recorder.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "仅开放实验性文本发送") {
		t.Fatalf("unexpected response: %s", recorder.Body.String())
	}
}
