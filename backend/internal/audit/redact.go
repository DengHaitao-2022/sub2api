package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"unicode/utf8"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/util/logredact"
)

const (
	captureModeNone    = "none"
	captureModeHash    = "hash"
	captureModePreview = "preview"
	captureModeFull    = "full"

	inputMessagePolicyAll             = "all"
	inputMessagePolicyUserMessages    = "user_messages"
	inputMessagePolicyLastUserMessage = "last_user_message"
	inputMessagePolicyMetadataOnly    = "metadata_only"
)

func normalizeCaptureMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case captureModeNone, captureModeHash, captureModeFull:
		return strings.ToLower(strings.TrimSpace(mode))
	default:
		return captureModePreview
	}
}

func normalizeInputMessagePolicy(policy string) string {
	switch strings.ToLower(strings.TrimSpace(policy)) {
	case inputMessagePolicyUserMessages, inputMessagePolicyLastUserMessage, inputMessagePolicyMetadataOnly:
		return strings.ToLower(strings.TrimSpace(policy))
	default:
		return inputMessagePolicyAll
	}
}

func BuildBodyRecord(raw []byte, contentType string, mode string, cfg config.GatewayAuditConfig, output bool) *BodyRecord {
	mode = normalizeCaptureMode(mode)
	if mode == captureModeNone {
		return nil
	}

	sum := sha256.Sum256(raw)
	record := &BodyRecord{
		SHA256:      hex.EncodeToString(sum[:]),
		SizeBytes:   int64(len(raw)),
		ContentType: strings.TrimSpace(contentType),
	}
	if mode == captureModeHash {
		return record
	}

	filteredRaw := raw
	if !output {
		filteredRaw = applyInputMessagePolicyRaw(raw, cfg.InputMessagePolicy)
	}
	maxBytes := bodyCaptureLimit(cfg, mode, output)
	captured := filteredRaw
	if maxBytes > 0 && int64(len(captured)) > maxBytes {
		captured = captured[:maxBytes]
		record.Truncated = true
	}

	record.Body = redactedBody(captured, cfg, mode == captureModeFull)
	return record
}

func applyInputMessagePolicyRaw(raw []byte, policy string) []byte {
	policy = normalizeInputMessagePolicy(policy)
	if policy == inputMessagePolicyAll || len(raw) == 0 || !json.Valid(raw) {
		return raw
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return raw
	}
	filtered, ok := filterInputMessageValue(value, policy)
	if !ok {
		return raw
	}
	encoded, err := json.Marshal(filtered)
	if err != nil {
		return raw
	}
	return encoded
}

func filterInputMessageValue(value any, policy string) (any, bool) {
	switch v := value.(type) {
	case map[string]any:
		return filterInputMessageObject(v, policy), true
	case []any:
		if policy == inputMessagePolicyMetadataOnly {
			return []any{}, true
		}
		return filterMessageItems(v, policy, false), true
	default:
		if policy == inputMessagePolicyMetadataOnly {
			return nil, true
		}
		return value, true
	}
}

func filterInputMessageObject(in map[string]any, policy string) map[string]any {
	out := make(map[string]any, len(in))
	for key, value := range in {
		if isGatewayAuditContentContextKey(key) {
			continue
		}
		out[key] = value
	}
	if policy == inputMessagePolicyMetadataOnly {
		return out
	}

	if messages, ok := arrayValue(in["messages"]); ok {
		out["messages"] = filterMessageItems(messages, policy, false)
	}
	if input, exists := in["input"]; exists {
		switch v := input.(type) {
		case []any:
			out["input"] = filterMessageItems(v, policy, true)
		case string:
			out["input"] = v
		case map[string]any:
			if msg, ok := sanitizedUserMessage(v, true); ok {
				out["input"] = msg
			}
		}
	}
	if contents, ok := arrayValue(in["contents"]); ok {
		out["contents"] = filterGeminiContents(contents, policy)
	}
	if prompt, exists := in["prompt"]; exists {
		out["prompt"] = prompt
	}
	return out
}

func isGatewayAuditContentContextKey(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "messages", "input", "contents", "system", "instructions", "tools", "tool_choice", "response_format", "text", "prompt":
		return true
	default:
		return false
	}
}

func arrayValue(value any) ([]any, bool) {
	items, ok := value.([]any)
	return items, ok
}

func filterMessageItems(items []any, policy string, requireMessageType bool) []any {
	filtered := make([]any, 0, len(items))
	for _, item := range items {
		msg, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if sanitized, ok := sanitizedUserMessage(msg, requireMessageType); ok {
			filtered = append(filtered, sanitized)
		}
	}
	if policy == inputMessagePolicyLastUserMessage && len(filtered) > 1 {
		return filtered[len(filtered)-1:]
	}
	return filtered
}

func sanitizedUserMessage(msg map[string]any, requireMessageType bool) (map[string]any, bool) {
	if strings.ToLower(strings.TrimSpace(stringValue(msg["role"]))) != "user" {
		return nil, false
	}
	if requireMessageType {
		msgType := strings.ToLower(strings.TrimSpace(stringValue(msg["type"])))
		if msgType != "" && msgType != "message" {
			return nil, false
		}
	}
	out := make(map[string]any, len(msg))
	for key, value := range msg {
		out[key] = value
	}
	if content, exists := msg["content"]; exists {
		filteredContent, ok := filterUserContentValue(content)
		if !ok {
			return nil, false
		}
		out["content"] = filteredContent
	}
	return out, true
}

func filterUserContentValue(content any) (any, bool) {
	switch v := content.(type) {
	case string:
		return v, strings.TrimSpace(v) != ""
	case []any:
		parts := make([]any, 0, len(v))
		for _, item := range v {
			part, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if sanitized, ok := sanitizedUserContentPart(part); ok {
				parts = append(parts, sanitized)
			}
		}
		return parts, len(parts) > 0
	default:
		return content, content != nil
	}
}

func sanitizedUserContentPart(part map[string]any) (map[string]any, bool) {
	partType := strings.ToLower(strings.TrimSpace(stringValue(part["type"])))
	if partType != "" && partType != "text" && partType != "input_text" {
		return nil, false
	}
	if _, hasText := part["text"]; !hasText && partType == "" {
		return nil, false
	}
	out := make(map[string]any, len(part))
	for key, value := range part {
		out[key] = value
	}
	return out, true
}

func filterGeminiContents(items []any, policy string) []any {
	filtered := make([]any, 0, len(items))
	for _, item := range items {
		msg, ok := item.(map[string]any)
		if !ok || strings.ToLower(strings.TrimSpace(stringValue(msg["role"]))) != "user" {
			continue
		}
		out := make(map[string]any, len(msg))
		for key, value := range msg {
			out[key] = value
		}
		if parts, ok := arrayValue(msg["parts"]); ok {
			filteredParts := make([]any, 0, len(parts))
			for _, item := range parts {
				part, ok := item.(map[string]any)
				if !ok {
					continue
				}
				if _, hasText := part["text"]; !hasText {
					continue
				}
				filteredParts = append(filteredParts, part)
			}
			if len(filteredParts) == 0 {
				continue
			}
			out["parts"] = filteredParts
		}
		filtered = append(filtered, out)
	}
	if policy == inputMessagePolicyLastUserMessage && len(filtered) > 1 {
		return filtered[len(filtered)-1:]
	}
	return filtered
}

func stringValue(value any) string {
	s, _ := value.(string)
	return s
}

func bodyCaptureLimit(cfg config.GatewayAuditConfig, mode string, output bool) int64 {
	var value int64
	var fallback int64
	var fullMax int64
	if output {
		value = cfg.MaxOutputBodyBytes
		fallback = config.DefaultGatewayAuditMaxOutputBodyBytes
		fullMax = config.MaxGatewayAuditFullOutputBodyBytes
	} else {
		value = cfg.MaxInputBodyBytes
		fallback = config.DefaultGatewayAuditMaxInputBodyBytes
		fullMax = config.MaxGatewayAuditFullInputBodyBytes
	}
	if value <= 0 {
		value = fallback
	}
	if normalizeCaptureMode(mode) == captureModeFull && fullMax > 0 && value > fullMax {
		return fullMax
	}
	return value
}

func redactedBody(raw []byte, cfg config.GatewayAuditConfig, preserveFull bool) any {
	if len(raw) == 0 {
		return ""
	}
	if json.Valid(raw) {
		redacted := logredact.RedactJSON(raw, cfg.RedactKeys...)
		var value any
		if err := json.Unmarshal([]byte(redacted), &value); err == nil {
			if preserveFull {
				return value
			}
			return limitValue(value, normalizeLimits(cfg), 0)
		}
		if preserveFull {
			return redacted
		}
		return truncateUTF8(redacted, cfg.MaxStringValueBytes)
	}
	text := logredact.RedactText(string(raw), cfg.RedactKeys...)
	if preserveFull {
		return text
	}
	return truncateUTF8(text, cfg.MaxStringValueBytes)
}

type limits struct {
	maxStringBytes int
	maxArrayItems  int
	maxObjectDepth int
}

func normalizeLimits(cfg config.GatewayAuditConfig) limits {
	out := limits{
		maxStringBytes: cfg.MaxStringValueBytes,
		maxArrayItems:  cfg.MaxArrayItems,
		maxObjectDepth: cfg.MaxObjectDepth,
	}
	if out.maxStringBytes <= 0 {
		out.maxStringBytes = 8192
	}
	if out.maxArrayItems <= 0 {
		out.maxArrayItems = 50
	}
	if out.maxObjectDepth <= 0 {
		out.maxObjectDepth = 16
	}
	return out
}

func limitValue(value any, lim limits, depth int) any {
	if depth > lim.maxObjectDepth {
		return "<depth limit exceeded>"
	}
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[key] = limitValue(item, lim, depth+1)
		}
		return out
	case []any:
		truncated := false
		if len(v) > lim.maxArrayItems {
			v = v[:lim.maxArrayItems]
			truncated = true
		}
		out := make([]any, 0, len(v)+1)
		for _, item := range v {
			out = append(out, limitValue(item, lim, depth+1))
		}
		if truncated {
			out = append(out, map[string]any{"_truncated": true})
		}
		return out
	case string:
		return truncateUTF8(v, lim.maxStringBytes)
	default:
		return value
	}
}

func truncateUTF8(value string, maxBytes int) string {
	if maxBytes <= 0 || len(value) <= maxBytes {
		return value
	}
	if maxBytes <= len("...(truncated)") {
		maxBytes = len("...(truncated)") + 1
	}
	limit := maxBytes - len("...(truncated)")
	cut := value[:limit]
	for !utf8.ValidString(cut) && len(cut) > 0 {
		cut = cut[:len(cut)-1]
	}
	return cut + "...(truncated)"
}
