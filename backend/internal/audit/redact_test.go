package audit

import (
	"crypto/sha256"
	"encoding/hex"
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
