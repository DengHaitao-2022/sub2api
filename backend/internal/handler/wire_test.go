package handler

import (
	"os"
	"strings"
	"testing"
)

func TestProviderSetIncludesAuditHandler(t *testing.T) {
	raw, err := os.ReadFile("wire.go")
	if err != nil {
		t.Fatalf("read wire.go: %v", err)
	}
	if !strings.Contains(string(raw), "admin.NewAuditHandler") {
		t.Fatal("ProviderSet must include admin.NewAuditHandler so wire_gen.go stays reproducible")
	}
}
