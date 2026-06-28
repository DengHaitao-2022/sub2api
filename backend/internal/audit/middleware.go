package audit

import (
	"bytes"
	"context"
	"hash/fnv"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/domain"
	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
	"github.com/Wei-Shaw/sub2api/internal/pkg/ip"
	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"
)

const opsTimeToFirstTokenMsKey = "ops_time_to_first_token_ms"

type GatewayAuditEnabledFunc func(context.Context) bool

func GatewayAuditMiddleware(cfg config.GatewayAuditConfig, enabledCheck ...GatewayAuditEnabledFunc) gin.HandlerFunc {
	cfg = normalizeConfig(cfg)
	return func(c *gin.Context) {
		if c == nil {
			return
		}
		if c.Request == nil || !gatewayAuditEnabled(c.Request.Context(), cfg, enabledCheck...) || !shouldCapture(c, cfg) {
			c.Next()
			return
		}

		started := time.Now()
		auditCtx := newContext(cfg, started)
		Attach(c, auditCtx)

		writer := NewResponseWriter(c.Writer, outputCaptureBytes(cfg))
		c.Writer = writer

		c.Next()

		event := buildFinalEvent(c, auditCtx, writer, time.Since(started))
		if err := WriteEvent(c.Request.Context(), cfg, event); err != nil {
			logger.FromContext(c.Request.Context()).Warn("gateway.audit.write_failed", zap.Error(err))
		}
	}
}

func gatewayAuditEnabled(ctx context.Context, cfg config.GatewayAuditConfig, checks ...GatewayAuditEnabledFunc) bool {
	if len(checks) == 0 || checks[0] == nil {
		return cfg.Enabled
	}
	return checks[0](ctx)
}

func normalizeConfig(cfg config.GatewayAuditConfig) config.GatewayAuditConfig {
	cfg.InputCaptureMode = normalizeCaptureMode(cfg.InputCaptureMode)
	cfg.OutputCaptureMode = normalizeCaptureMode(cfg.OutputCaptureMode)
	if cfg.SampleRate <= 0 {
		cfg.SampleRate = 0
	}
	if cfg.SampleRate > 1 {
		cfg.SampleRate = 1
	}
	return cfg
}

func outputCaptureBytes(cfg config.GatewayAuditConfig) int64 {
	switch normalizeCaptureMode(cfg.OutputCaptureMode) {
	case captureModeNone, captureModeHash:
		return 0
	default:
		return cfg.MaxOutputBodyBytes
	}
}

func shouldCapture(c *gin.Context, cfg config.GatewayAuditConfig) bool {
	path := requestPath(c)
	if pathMatches(path, cfg.ExcludePaths) {
		return false
	}
	if len(cfg.IncludePaths) > 0 && !pathMatches(path, cfg.IncludePaths) {
		return false
	}
	if cfg.SampleRate >= 1 {
		return true
	}
	if cfg.SampleRate <= 0 {
		return false
	}
	clientRequestID, _ := c.Request.Context().Value(ctxkey.ClientRequestID).(string)
	key := strings.TrimSpace(clientRequestID)
	if key == "" {
		key = path
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return float64(h.Sum32()%10000)/10000 < cfg.SampleRate
}

func pathMatches(path string, patterns []string) bool {
	path = strings.TrimRight(strings.TrimSpace(path), "/")
	if path == "" {
		path = "/"
	}
	for _, pattern := range patterns {
		pattern = strings.TrimRight(strings.TrimSpace(pattern), "/")
		if pattern == "" {
			continue
		}
		if path == pattern || strings.HasPrefix(path, pattern+"/") {
			return true
		}
	}
	return false
}

func buildFinalEvent(c *gin.Context, auditCtx *Context, writer *ResponseWriter, duration time.Duration) *Event {
	input, model, stream, account, attempts := snapshotState(auditCtx)
	event := &Event{
		Timestamp:  time.Now(),
		Event:      eventGatewayRequestCompleted,
		AuditID:    "aud_" + strings.ReplaceAll(uuid.NewString(), "-", ""),
		Method:     c.Request.Method,
		Path:       requestPath(c),
		ClientIP:   ip.GetClientIP(c),
		UserAgent:  c.GetHeader("User-Agent"),
		Input:      input,
		StatusCode: writer.StatusCode(),
		DurationMs: duration.Milliseconds(),
	}

	if requestID, _ := c.Request.Context().Value(ctxkey.RequestID).(string); strings.TrimSpace(requestID) != "" {
		event.RequestID = strings.TrimSpace(requestID)
	}
	if clientRequestID, _ := c.Request.Context().Value(ctxkey.ClientRequestID).(string); strings.TrimSpace(clientRequestID) != "" {
		event.ClientRequestID = strings.TrimSpace(clientRequestID)
	}
	event.InboundEndpoint = inboundEndpoint(c)

	if apiKey := apiKeyInfoFromGin(c); apiKey.APIKeyID > 0 {
		event.APIKeyID = apiKey.APIKeyID
		event.UserID = apiKey.UserID
		event.GroupID = apiKey.GroupID
		event.Platform = apiKey.Platform
	}
	if userID := authSubjectUserIDFromGin(c); userID > 0 {
		event.UserID = userID
	}
	if platform, _ := c.Request.Context().Value(ctxkey.Platform).(string); strings.TrimSpace(platform) != "" {
		if event.Platform == "" {
			event.Platform = strings.TrimSpace(platform)
		}
	}

	event.Model = model
	event.Stream = stream
	event.AccountID = account.AccountID
	event.AccountName = account.AccountName
	event.AccountPlatform = account.Platform
	event.UpstreamEndpoint = strings.TrimSpace(account.UpstreamEndpoint)
	event.Attempts = attempts
	if event.UpstreamEndpoint == "" {
		event.UpstreamEndpoint = deriveUpstreamEndpoint(event.InboundEndpoint, event.Path, account.Platform)
	}
	if event.Platform == "" && account.Platform != "" {
		event.Platform = account.Platform
	}

	event.Output = buildOutputRecord(writer, c.Writer.Header().Get("Content-Type"), auditCtx.cfg)
	event.Usage = parseUsage(writer.PreviewBytes())
	event.TimeToFirstTokenMs = contextInt64(c, opsTimeToFirstTokenMsKey)
	fillErrorFields(event)
	return event
}

func buildOutputRecord(writer *ResponseWriter, contentType string, cfg config.GatewayAuditConfig) *BodyRecord {
	mode := normalizeCaptureMode(cfg.OutputCaptureMode)
	if mode == captureModeNone {
		return nil
	}
	record := &BodyRecord{
		SHA256:      writer.SHA256Hex(),
		SizeBytes:   writer.SizeBytes(),
		Truncated:   writer.Truncated(),
		ContentType: strings.TrimSpace(contentType),
	}
	if mode == captureModeHash {
		return record
	}
	preview := writer.PreviewBytes()
	if isBinaryLikeOutput(contentType, preview) {
		return record
	}
	record.Body = redactedBody(preview, cfg)
	return record
}

func isBinaryLikeOutput(contentType string, preview []byte) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if strings.HasPrefix(ct, "image/") || strings.HasPrefix(ct, "audio/") || strings.HasPrefix(ct, "video/") ||
		strings.Contains(ct, "octet-stream") {
		return true
	}
	lower := bytes.ToLower(preview)
	return bytes.Contains(lower, []byte(`"b64_json"`)) || bytes.Contains(lower, []byte("data:image/"))
}

func parseUsage(preview []byte) *UsageRecord {
	if len(preview) == 0 {
		return nil
	}
	if gjson.ValidBytes(preview) {
		return usageFromJSON(gjson.ParseBytes(preview))
	}
	var out *UsageRecord
	for _, line := range bytes.Split(preview, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		payload := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
		if bytes.Equal(payload, []byte("[DONE]")) || !gjson.ValidBytes(payload) {
			continue
		}
		if usage := usageFromJSON(gjson.ParseBytes(payload)); usage != nil {
			out = usage
		}
	}
	return out
}

func usageFromJSON(result gjson.Result) *UsageRecord {
	if !result.Exists() {
		return nil
	}
	input := firstInt64(
		result.Get("usage.input_tokens"),
		result.Get("usage.prompt_tokens"),
		result.Get("response.usage.input_tokens"),
		result.Get("response.usage.prompt_tokens"),
	)
	output := firstInt64(
		result.Get("usage.output_tokens"),
		result.Get("usage.completion_tokens"),
		result.Get("response.usage.output_tokens"),
		result.Get("response.usage.completion_tokens"),
	)
	if input == 0 && output == 0 {
		return nil
	}
	return &UsageRecord{InputTokens: input, OutputTokens: output}
}

func firstInt64(values ...gjson.Result) int64 {
	for _, value := range values {
		if value.Exists() {
			return value.Int()
		}
	}
	return 0
}

func fillErrorFields(event *Event) {
	if event == nil || event.StatusCode < http.StatusBadRequest || event.Output == nil {
		return
	}
	body, ok := event.Output.Body.(map[string]any)
	if !ok {
		if text, ok := event.Output.Body.(string); ok {
			event.ErrorMessage = text
		}
		return
	}
	if errObj, ok := body["error"].(map[string]any); ok {
		if v, ok := errObj["type"].(string); ok {
			event.ErrorType = v
		}
		if v, ok := errObj["message"].(string); ok {
			event.ErrorMessage = v
		}
		return
	}
	if v, ok := body["type"].(string); ok {
		event.ErrorType = v
	}
	if v, ok := body["message"].(string); ok {
		event.ErrorMessage = v
	}
}

func requestPath(c *gin.Context) string {
	if c == nil || c.Request == nil || c.Request.URL == nil {
		return ""
	}
	return c.Request.URL.Path
}

func inboundEndpoint(c *gin.Context) string {
	if c == nil {
		return ""
	}
	if value, ok := c.Get("_gateway_inbound_endpoint"); ok {
		if s, ok := value.(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return normalizeInboundEndpoint(requestPath(c))
}

func normalizeInboundEndpoint(path string) string {
	switch {
	case strings.Contains(path, "/v1/embeddings") || strings.HasSuffix(path, "/embeddings"):
		return "/v1/embeddings"
	case strings.Contains(path, "/v1/chat/completions") || strings.HasSuffix(path, "/chat/completions"):
		return "/v1/chat/completions"
	case strings.Contains(path, "/v1/messages"):
		return "/v1/messages"
	case strings.Contains(path, "/v1/images/generations") || strings.Contains(path, "/images/generations"):
		return "/v1/images/generations"
	case strings.Contains(path, "/v1/images/edits") || strings.Contains(path, "/images/edits"):
		return "/v1/images/edits"
	case strings.Contains(path, "/v1/responses") || strings.Contains(path, "/responses"):
		return "/v1/responses"
	case strings.Contains(path, "/v1beta/models"):
		return "/v1beta/models"
	default:
		return path
	}
}

func deriveUpstreamEndpoint(inbound, rawPath, platform string) string {
	switch strings.TrimSpace(platform) {
	case domain.PlatformOpenAI, domain.PlatformGrok:
		if inbound == "/v1/embeddings" || inbound == "/v1/images/generations" || inbound == "/v1/images/edits" {
			return inbound
		}
		if suffix := responsesSubpathSuffix(rawPath); suffix != "" {
			return "/v1/responses" + suffix
		}
		return "/v1/responses"
	case domain.PlatformAnthropic:
		return "/v1/messages"
	case domain.PlatformGemini:
		return "/v1beta/models"
	case domain.PlatformAntigravity:
		if inbound == "/v1beta/models" {
			return "/v1beta/models"
		}
		return "/v1/messages"
	default:
		return inbound
	}
}

func responsesSubpathSuffix(rawPath string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(rawPath), "/")
	idx := strings.LastIndex(trimmed, "/responses")
	if idx < 0 {
		return ""
	}
	suffix := trimmed[idx+len("/responses"):]
	if suffix == "" || suffix == "/" || !strings.HasPrefix(suffix, "/") {
		return ""
	}
	return suffix
}

func contextInt64(c *gin.Context, key string) int64 {
	if c == nil {
		return 0
	}
	value, ok := c.Get(key)
	if !ok {
		return 0
	}
	switch v := value.(type) {
	case int64:
		return v
	case int:
		return int64(v)
	case float64:
		return int64(v)
	case string:
		if parsed := gjson.Parse(v); parsed.Exists() {
			return parsed.Int()
		}
	}
	return 0
}

type apiKeyContextInfo struct {
	APIKeyID int64
	UserID   int64
	GroupID  int64
	Platform string
}

func apiKeyInfoFromGin(c *gin.Context) apiKeyContextInfo {
	value, ok := c.Get("api_key")
	if !ok || value == nil {
		return apiKeyContextInfo{}
	}
	root := reflect.Indirect(reflect.ValueOf(value))
	if !root.IsValid() || root.Kind() != reflect.Struct {
		return apiKeyContextInfo{}
	}
	info := apiKeyContextInfo{
		APIKeyID: reflectInt64Field(root, "ID"),
		UserID:   reflectInt64Field(root, "UserID"),
	}
	if groupID := root.FieldByName("GroupID"); groupID.IsValid() && !groupID.IsNil() {
		info.GroupID = reflectInt64Value(reflect.Indirect(groupID))
	}
	if user := root.FieldByName("User"); user.IsValid() && !user.IsNil() {
		userValue := reflect.Indirect(user)
		if id := reflectInt64Field(userValue, "ID"); id > 0 {
			info.UserID = id
		}
	}
	if group := root.FieldByName("Group"); group.IsValid() && !group.IsNil() {
		groupValue := reflect.Indirect(group)
		if platform := reflectStringField(groupValue, "Platform"); platform != "" {
			info.Platform = platform
		}
	}
	return info
}

func authSubjectUserIDFromGin(c *gin.Context) int64 {
	value, ok := c.Get("user")
	if !ok || value == nil {
		return 0
	}
	root := reflect.Indirect(reflect.ValueOf(value))
	if !root.IsValid() || root.Kind() != reflect.Struct {
		return 0
	}
	return reflectInt64Field(root, "UserID")
}

func reflectInt64Field(v reflect.Value, name string) int64 {
	field := v.FieldByName(name)
	if !field.IsValid() {
		return 0
	}
	return reflectInt64Value(field)
}

func reflectInt64Value(v reflect.Value) int64 {
	if !v.IsValid() {
		return 0
	}
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return int64(v.Uint())
	default:
		return 0
	}
}

func reflectStringField(v reflect.Value, name string) string {
	field := v.FieldByName(name)
	if !field.IsValid() || field.Kind() != reflect.String {
		return ""
	}
	return strings.TrimSpace(field.String())
}
