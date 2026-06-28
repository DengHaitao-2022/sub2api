package audit

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/gin-gonic/gin"
)

func TestGatewayAuditMiddlewareWritesJSONL(t *testing.T) {
	gin.SetMode(gin.TestMode)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	cfg := config.GatewayAuditConfig{
		Enabled:             true,
		InputCaptureMode:    "preview",
		OutputCaptureMode:   "preview",
		FileEnabled:         true,
		FilePath:            path,
		MaxInputBodyBytes:   1024,
		MaxOutputBodyBytes:  1024,
		MaxStringValueBytes: 1024,
		MaxArrayItems:       10,
		MaxObjectDepth:      8,
		SampleRate:          1,
		IncludePaths:        []string{"/v1/test"},
		RedactKeys:          []string{"api_key"},
	}

	r := gin.New()
	r.Use(GatewayAuditMiddleware(cfg))
	r.POST("/v1/test", func(c *gin.Context) {
		CaptureInput(c, InputSnapshot{
			Protocol: "openai",
			Endpoint: "responses",
			Model:    "gpt-test",
			Stream:   true,
			Body:     []byte(`{"api_key":"secret","model":"gpt-test"}`),
		})
		MarkAccount(c, AccountSnapshot{AccountID: 12, AccountName: "acct", Platform: "openai"})
		MarkAccount(c, AccountSnapshot{AccountID: 13, AccountName: "acct-2", Platform: "openai", UpstreamEndpoint: "/v1/responses"})
		c.JSON(http.StatusOK, gin.H{"ok": true, "api_key": "secret"})
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/test", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit jsonl: %v", err)
	}
	var event Event
	if err := json.Unmarshal(raw, &event); err != nil {
		t.Fatalf("unmarshal audit event: %v raw=%s", err, string(raw))
	}
	if event.Event != eventGatewayRequestCompleted {
		t.Fatalf("event = %q", event.Event)
	}
	if event.Model != "gpt-test" || event.Stream == nil || !*event.Stream {
		t.Fatalf("model/stream not captured: model=%q stream=%v", event.Model, event.Stream)
	}
	if event.AccountID != 13 || event.AccountName != "acct-2" {
		t.Fatalf("account not captured: %#v", event)
	}
	if len(event.Attempts) != 2 || event.Attempts[0].AccountID != 12 || event.Attempts[1].AccountID != 13 {
		t.Fatalf("attempt chain not captured: %#v", event.Attempts)
	}
	input := event.Input.Body.(map[string]any)
	if got := input["api_key"]; got != "***" {
		t.Fatalf("input api_key not redacted: %#v", got)
	}
	output := event.Output.Body.(map[string]any)
	if got := output["api_key"]; got != "***" {
		t.Fatalf("output api_key not redacted: %#v", got)
	}
}

func TestAuditResponseWriterReadFromCapturesBody(t *testing.T) {
	w := NewResponseWriter(&responseWriterStub{header: http.Header{}}, 4)
	n, err := w.ReadFrom(strings.NewReader("abcdef"))
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if n != 6 {
		t.Fatalf("n = %d", n)
	}
	if w.SizeBytes() != 6 {
		t.Fatalf("size = %d", w.SizeBytes())
	}
	if string(w.PreviewBytes()) != "abcd" {
		t.Fatalf("preview = %q", string(w.PreviewBytes()))
	}
	if !w.Truncated() {
		t.Fatal("expected truncated")
	}
	if w.SHA256Hex() == "" {
		t.Fatal("expected hash")
	}
}

var _ io.ReaderFrom = (*ResponseWriter)(nil)

func TestBuildOutputRecordOmitsImageBase64Body(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := NewResponseWriter(&responseWriterStub{header: http.Header{}}, 4096)
	_, _ = w.Write([]byte(`{"data":[{"b64_json":"abc123"}],"usage":{"input_tokens":3,"output_tokens":4}}`))

	record := buildOutputRecord(w, "application/json", config.GatewayAuditConfig{OutputCaptureMode: "preview"})
	if record == nil {
		t.Fatal("expected output record")
	}
	if record.Body != nil {
		t.Fatalf("expected base64 output body omitted, got %#v", record.Body)
	}
	usage := parseUsage(w.PreviewBytes())
	if usage == nil || usage.InputTokens != 3 || usage.OutputTokens != 4 {
		t.Fatalf("usage not parsed: %#v", usage)
	}
}

type responseWriterStub struct {
	gin.ResponseWriter
	header http.Header
}

func (w *responseWriterStub) Header() http.Header { return w.header }

func (w *responseWriterStub) Write(data []byte) (int, error) { return len(data), nil }

func (w *responseWriterStub) WriteHeaderNow() {}

func (w *responseWriterStub) WriteHeader(int) {}

func (w *responseWriterStub) Status() int { return http.StatusOK }

func (w *responseWriterStub) Size() int { return 0 }

func (w *responseWriterStub) Written() bool { return false }

func (w *responseWriterStub) WriteString(data string) (int, error) { return len(data), nil }

func (w *responseWriterStub) Pusher() http.Pusher { return nil }

func (w *responseWriterStub) Flush() {}

func (w *responseWriterStub) CloseNotify() <-chan bool { return make(chan bool) }

func (w *responseWriterStub) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, http.ErrNotSupported
}

func TestShouldCaptureHonorsIncludeExcludeAndSample(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/health", nil)
	cfg := config.GatewayAuditConfig{Enabled: true, SampleRate: 1, ExcludePaths: []string{"/health"}}
	if shouldCapture(c, cfg) {
		t.Fatal("excluded path should not be captured")
	}

	c.Request = httptest.NewRequest(http.MethodGet, "/v1/messages", nil)
	cfg = config.GatewayAuditConfig{Enabled: true, SampleRate: 1, IncludePaths: []string{"/v1/responses"}}
	if shouldCapture(c, cfg) {
		t.Fatal("path outside include list should not be captured")
	}

	cfg = config.GatewayAuditConfig{Enabled: true, SampleRate: 0}
	if shouldCapture(c, cfg) {
		t.Fatal("zero sample rate should not capture")
	}
}
