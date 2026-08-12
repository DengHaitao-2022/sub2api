package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
)

func TestBuildBodyRecordRedactsAndTruncatesJSON(t *testing.T) {
	body := []byte(`{"model":"gpt-test","api_key":"secret","messages":[{"content":"hello"},{"content":"world"},{"content":"again"}],"nested":{"password":"pw"}}`)
	cfg := config.GatewayAuditConfig{
		InputCaptureMode:    "preview",
		MaxInputBodyBytes:   1024,
		MaxStringValueBytes: 64,
		MaxArrayItems:       2,
		MaxObjectDepth:      8,
		RedactKeys:          []string{"api_key", "password"},
	}

	record := BuildBodyRecord(body, "application/json", "preview", cfg, false)
	if record == nil {
		t.Fatal("expected body record")
	}
	sum := sha256.Sum256(body)
	if record.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("sha mismatch: %s", record.SHA256)
	}
	obj, ok := record.Body.(map[string]any)
	if !ok {
		t.Fatalf("expected structured JSON body, got %T", record.Body)
	}
	if got := obj["api_key"]; got != "***" {
		t.Fatalf("api_key not redacted: %#v", got)
	}
	nested := obj["nested"].(map[string]any)
	if got := nested["password"]; got != "***" {
		t.Fatalf("password not redacted: %#v", got)
	}
	messages := obj["messages"].([]any)
	if len(messages) != 3 {
		t.Fatalf("expected two messages plus truncation marker, got %d", len(messages))
	}
}

func TestBuildBodyRecordHashModeOmitsBody(t *testing.T) {
	record := BuildBodyRecord([]byte(`{"x":1}`), "application/json", "hash", config.GatewayAuditConfig{}, false)
	if record == nil {
		t.Fatal("expected hash record")
	}
	if record.Body != nil {
		t.Fatalf("hash mode should omit body, got %#v", record.Body)
	}
}

func TestBuildBodyRecordInputPolicyUserMessagesFiltersResponsesContext(t *testing.T) {
	body := []byte(`{
		"model":"gpt-test",
		"instructions":"developer context",
		"tools":[{"type":"function","name":"lookup"}],
		"input":[
			{"type":"message","role":"developer","content":[{"type":"input_text","text":"dev"}]},
			{"type":"message","role":"user","content":[{"type":"input_text","text":"first"},{"type":"input_image","image_url":"data:image/png;base64,abc"}]},
			{"type":"function_call","call_id":"call_1","name":"lookup","arguments":"{}"},
			{"type":"function_call_output","call_id":"call_1","output":"tool output"},
			{"type":"message","role":"assistant","content":[{"type":"output_text","text":"answer"}]},
			{"type":"message","role":"user","content":[{"type":"input_text","text":"latest"}]}
		]
	}`)
	record := BuildBodyRecord(body, "application/json", "preview", config.GatewayAuditConfig{
		InputMessagePolicy:  "user_messages",
		MaxInputBodyBytes:   4096,
		MaxStringValueBytes: 1024,
		MaxArrayItems:       10,
		MaxObjectDepth:      10,
	}, false)

	obj, ok := record.Body.(map[string]any)
	if !ok {
		t.Fatalf("expected structured body, got %T", record.Body)
	}
	if _, ok := obj["instructions"]; ok {
		t.Fatalf("instructions should be removed: %#v", obj)
	}
	if _, ok := obj["tools"]; ok {
		t.Fatalf("tools should be removed: %#v", obj)
	}
	items, ok := obj["input"].([]any)
	if !ok || len(items) != 2 {
		t.Fatalf("expected two user messages, got %#v", obj["input"])
	}
	for _, item := range items {
		msg := item.(map[string]any)
		if msg["role"] != "user" || msg["type"] != "message" {
			t.Fatalf("unexpected input item: %#v", msg)
		}
		parts := msg["content"].([]any)
		if len(parts) != 1 || parts[0].(map[string]any)["type"] != "input_text" {
			t.Fatalf("expected only input_text content, got %#v", parts)
		}
	}
}

func TestBuildBodyRecordInputPolicyLastUserMessageFiltersMessages(t *testing.T) {
	body := []byte(`{"system":"sys","messages":[{"role":"system","content":"sys"},{"role":"user","content":"first"},{"role":"assistant","content":"answer"},{"role":"user","content":[{"type":"text","text":"latest"},{"type":"tool_result","content":"tool"}]}]}`)
	record := BuildBodyRecord(body, "application/json", "preview", config.GatewayAuditConfig{
		InputMessagePolicy:  "last_user_message",
		MaxInputBodyBytes:   4096,
		MaxStringValueBytes: 1024,
		MaxArrayItems:       10,
		MaxObjectDepth:      10,
	}, false)

	obj := record.Body.(map[string]any)
	if _, ok := obj["system"]; ok {
		t.Fatalf("system should be removed: %#v", obj)
	}
	messages := obj["messages"].([]any)
	if len(messages) != 1 {
		t.Fatalf("expected latest user message only, got %#v", messages)
	}
	msg := messages[0].(map[string]any)
	if msg["role"] != "user" {
		t.Fatalf("unexpected message: %#v", msg)
	}
	parts := msg["content"].([]any)
	if len(parts) != 1 || parts[0].(map[string]any)["text"] != "latest" {
		t.Fatalf("expected latest text part only, got %#v", parts)
	}
}

func TestBuildBodyRecordInputPolicyMetadataOnlyKeepsRequestMetadata(t *testing.T) {
	body := []byte(`{"model":"gpt-test","stream":true,"instructions":"sys","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"secret"}]}],"tools":[{"type":"function","name":"lookup"}]}`)
	record := BuildBodyRecord(body, "application/json", "preview", config.GatewayAuditConfig{
		InputMessagePolicy:  "metadata_only",
		MaxInputBodyBytes:   4096,
		MaxStringValueBytes: 1024,
		MaxArrayItems:       10,
		MaxObjectDepth:      10,
	}, false)

	obj := record.Body.(map[string]any)
	if obj["model"] != "gpt-test" || obj["stream"] != true {
		t.Fatalf("metadata not preserved: %#v", obj)
	}
	for _, key := range []string{"instructions", "input", "tools"} {
		if _, ok := obj[key]; ok {
			t.Fatalf("%s should be removed: %#v", key, obj)
		}
	}
}

func TestBuildBodyRecordFullModePreservesStructuredBody(t *testing.T) {
	body := []byte(`{"message":"1234567890","items":[{"content":"first"},{"content":"second"},{"content":"third"}],"secret":"keep-redacted"}`)
	cfg := config.GatewayAuditConfig{
		InputCaptureMode:    "full",
		MaxInputBodyBytes:   1024,
		MaxStringValueBytes: 4,
		MaxArrayItems:       1,
		MaxObjectDepth:      1,
		RedactKeys:          []string{"secret"},
	}

	record := BuildBodyRecord(body, "application/json", "full", cfg, false)
	if record == nil {
		t.Fatal("expected full record")
	}
	obj, ok := record.Body.(map[string]any)
	if !ok {
		t.Fatalf("expected structured JSON body, got %T", record.Body)
	}
	if got := obj["message"]; got != "1234567890" {
		t.Fatalf("full mode should preserve full string value, got %#v", got)
	}
	items, ok := obj["items"].([]any)
	if !ok {
		t.Fatalf("expected items array, got %T", obj["items"])
	}
	if len(items) != 3 {
		t.Fatalf("full mode should preserve full array length, got %d", len(items))
	}
	if got := obj["secret"]; got != "***" {
		t.Fatalf("redaction must still apply in full mode, got %#v", got)
	}
}

func TestBuildBodyRecordFullModeZeroLimitUsesDefault(t *testing.T) {
	body := []byte(strings.Repeat("x", int(config.DefaultGatewayAuditMaxInputBodyBytes)+1))
	record := BuildBodyRecord(body, "text/plain", "full", config.GatewayAuditConfig{
		MaxInputBodyBytes: 0,
	}, false)
	if record == nil {
		t.Fatal("expected full record")
	}
	if !record.Truncated {
		t.Fatal("full mode with zero limit should use default limit and truncate oversized input")
	}
	if got := len(record.Body.(string)); got != int(config.DefaultGatewayAuditMaxInputBodyBytes) {
		t.Fatalf("captured bytes = %d, want default %d", got, config.DefaultGatewayAuditMaxInputBodyBytes)
	}
}

func TestBuildBodyRecordFullModeOutputZeroLimitUsesDefault(t *testing.T) {
	body := []byte(strings.Repeat("x", int(config.DefaultGatewayAuditMaxOutputBodyBytes)+1))
	record := BuildBodyRecord(body, "text/plain", "full", config.GatewayAuditConfig{
		MaxOutputBodyBytes: 0,
	}, true)
	if record == nil {
		t.Fatal("expected full output record")
	}
	if !record.Truncated {
		t.Fatal("full output mode with zero limit should use default limit and truncate oversized output")
	}
	if got := len(record.Body.(string)); got != int(config.DefaultGatewayAuditMaxOutputBodyBytes) {
		t.Fatalf("captured bytes = %d, want default %d", got, config.DefaultGatewayAuditMaxOutputBodyBytes)
	}
}

func TestBuildBodyRecordFullModeHardCapsAndRedacts(t *testing.T) {
	body := []byte(`{"secret":"keep-redacted","payload":"` + strings.Repeat("x", int(config.MaxGatewayAuditFullInputBodyBytes)) + `"}`)
	record := BuildBodyRecord(body, "application/json", "full", config.GatewayAuditConfig{
		MaxInputBodyBytes: config.MaxGatewayAuditFullInputBodyBytes + 1024,
		RedactKeys:        []string{"secret"},
	}, false)
	if record == nil {
		t.Fatal("expected full record")
	}
	if !record.Truncated {
		t.Fatal("full mode should truncate at hard cap")
	}
	if record.SizeBytes != int64(len(body)) {
		t.Fatalf("size bytes = %d, want %d", record.SizeBytes, len(body))
	}
	bodyText, ok := record.Body.(string)
	if !ok {
		t.Fatalf("expected truncated invalid JSON to be stored as text, got %T", record.Body)
	}
	if strings.Contains(bodyText, "keep-redacted") {
		t.Fatalf("redaction must still apply in truncated full mode, got prefix %.80q", bodyText)
	}
}
