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
)

func normalizeCaptureMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case captureModeNone, captureModeHash, captureModeFull:
		return strings.ToLower(strings.TrimSpace(mode))
	default:
		return captureModePreview
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

	maxBytes := cfg.MaxInputBodyBytes
	if output {
		maxBytes = cfg.MaxOutputBodyBytes
	}
	captured := raw
	if maxBytes > 0 && int64(len(captured)) > maxBytes {
		captured = captured[:maxBytes]
		record.Truncated = true
	}

	record.Body = redactedBody(captured, cfg)
	return record
}

func redactedBody(raw []byte, cfg config.GatewayAuditConfig) any {
	if len(raw) == 0 {
		return ""
	}
	if json.Valid(raw) {
		redacted := logredact.RedactJSON(raw, cfg.RedactKeys...)
		var value any
		if err := json.Unmarshal([]byte(redacted), &value); err == nil {
			return limitValue(value, normalizeLimits(cfg), 0)
		}
		return truncateUTF8(redacted, cfg.MaxStringValueBytes)
	}
	text := logredact.RedactText(string(raw), cfg.RedactKeys...)
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
