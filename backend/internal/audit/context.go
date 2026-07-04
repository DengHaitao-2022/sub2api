package audit

import (
	"strings"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/gin-gonic/gin"
)

const contextKey = "_gateway_audit_context"

type Context struct {
	cfg      config.GatewayAuditConfig
	started  time.Time
	captured bool

	mu       sync.Mutex
	input    *BodyRecord
	model    string
	stream   *bool
	account  AccountSnapshot
	attempts []AttemptRecord
}

func newContext(cfg config.GatewayAuditConfig, started time.Time) *Context {
	return &Context{cfg: cfg, started: started, captured: true}
}

func Attach(c *gin.Context, ctx *Context) {
	if c == nil || ctx == nil {
		return
	}
	c.Set(contextKey, ctx)
}

func FromContext(c *gin.Context) (*Context, bool) {
	if c == nil {
		return nil, false
	}
	value, ok := c.Get(contextKey)
	if !ok {
		return nil, false
	}
	ctx, ok := value.(*Context)
	return ctx, ok && ctx != nil && ctx.captured
}

func CaptureInput(c *gin.Context, snapshot InputSnapshot) {
	ctx, ok := FromContext(c)
	if !ok {
		return
	}
	mode := normalizeCaptureMode(ctx.cfg.InputCaptureMode)
	if strings.TrimSpace(snapshot.CaptureMode) != "" {
		mode = normalizeCaptureMode(snapshot.CaptureMode)
	}
	record := BuildBodyRecord(snapshot.Body, snapshot.ContentType, mode, ctx.cfg, false)
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	ctx.input = record
	if model := strings.TrimSpace(snapshot.Model); model != "" {
		ctx.model = model
	}
	stream := snapshot.Stream
	ctx.stream = &stream
}

func MarkAccount(c *gin.Context, snapshot AccountSnapshot) {
	ctx, ok := FromContext(c)
	if !ok {
		return
	}
	if snapshot.AccountID <= 0 {
		return
	}
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	ctx.account = snapshot
	ctx.attempts = append(ctx.attempts, AttemptRecord{
		Attempt:          len(ctx.attempts) + 1,
		AccountID:        snapshot.AccountID,
		AccountName:      strings.TrimSpace(snapshot.AccountName),
		Platform:         strings.TrimSpace(snapshot.Platform),
		UpstreamEndpoint: strings.TrimSpace(snapshot.UpstreamEndpoint),
		SelectedAtMs:     time.Since(ctx.started).Milliseconds(),
	})
}

func MarkAttemptResult(c *gin.Context, snapshot AttemptResultSnapshot) {
	ctx, ok := FromContext(c)
	if !ok {
		return
	}
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	if len(ctx.attempts) == 0 {
		return
	}
	idx := len(ctx.attempts) - 1
	result := strings.TrimSpace(snapshot.Result)
	if result == "" {
		if snapshot.StatusCode >= 400 || strings.TrimSpace(snapshot.ErrorType) != "" || strings.TrimSpace(snapshot.ErrorMessage) != "" {
			result = "failed"
		} else {
			result = "completed"
		}
	}
	ctx.attempts[idx].StatusCode = snapshot.StatusCode
	ctx.attempts[idx].DurationMs = snapshot.DurationMs
	ctx.attempts[idx].ErrorType = strings.TrimSpace(snapshot.ErrorType)
	ctx.attempts[idx].ErrorMessage = strings.TrimSpace(snapshot.ErrorMessage)
	ctx.attempts[idx].Result = result
}

func snapshotState(ctx *Context) (*BodyRecord, string, *bool, AccountSnapshot, []AttemptRecord) {
	if ctx == nil {
		return nil, "", nil, AccountSnapshot{}, nil
	}
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	attempts := make([]AttemptRecord, len(ctx.attempts))
	copy(attempts, ctx.attempts)
	return ctx.input, ctx.model, ctx.stream, ctx.account, attempts
}
