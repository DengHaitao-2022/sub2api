package audit

import "time"

const eventGatewayRequestCompleted = "gateway.request.completed"

type Event struct {
	Timestamp       time.Time `json:"ts"`
	Event           string    `json:"event"`
	AuditID         string    `json:"audit_id,omitempty"`
	RequestID       string    `json:"request_id,omitempty"`
	ClientRequestID string    `json:"client_request_id,omitempty"`

	Method          string `json:"method,omitempty"`
	Path            string `json:"path,omitempty"`
	InboundEndpoint string `json:"inbound_endpoint,omitempty"`
	ClientIP        string `json:"client_ip,omitempty"`
	UserAgent       string `json:"user_agent,omitempty"`

	UserID   int64  `json:"user_id,omitempty"`
	APIKeyID int64  `json:"api_key_id,omitempty"`
	GroupID  int64  `json:"group_id,omitempty"`
	Platform string `json:"platform,omitempty"`

	Model  string `json:"model,omitempty"`
	Stream *bool  `json:"stream,omitempty"`

	AccountID        int64           `json:"account_id,omitempty"`
	AccountName      string          `json:"account_name,omitempty"`
	AccountPlatform  string          `json:"account_platform,omitempty"`
	UpstreamEndpoint string          `json:"upstream_endpoint,omitempty"`
	Attempts         []AttemptRecord `json:"attempts,omitempty"`

	Input  *BodyRecord `json:"input,omitempty"`
	Output *BodyRecord `json:"output,omitempty"`

	StatusCode         int   `json:"status_code,omitempty"`
	DurationMs         int64 `json:"duration_ms,omitempty"`
	TimeToFirstTokenMs int64 `json:"time_to_first_token_ms,omitempty"`

	Usage *UsageRecord `json:"usage,omitempty"`

	ErrorType    string `json:"error_type,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}

type BodyRecord struct {
	SHA256      string `json:"sha256,omitempty"`
	SizeBytes   int64  `json:"size_bytes"`
	Truncated   bool   `json:"truncated"`
	ContentType string `json:"content_type,omitempty"`
	Body        any    `json:"body,omitempty"`
}

type UsageRecord struct {
	InputTokens  int64 `json:"input_tokens,omitempty"`
	OutputTokens int64 `json:"output_tokens,omitempty"`
}

type InputSnapshot struct {
	Protocol    string
	Endpoint    string
	Model       string
	Stream      bool
	Body        []byte
	ContentType string
	CaptureMode string
}

type AccountSnapshot struct {
	AccountID        int64
	AccountName      string
	Platform         string
	UpstreamEndpoint string
}

type AttemptRecord struct {
	Attempt          int    `json:"attempt"`
	AccountID        int64  `json:"account_id,omitempty"`
	AccountName      string `json:"account_name,omitempty"`
	Platform         string `json:"platform,omitempty"`
	UpstreamEndpoint string `json:"upstream_endpoint,omitempty"`
	SelectedAtMs     int64  `json:"selected_at_ms,omitempty"`
	StatusCode       int    `json:"status_code,omitempty"`
	DurationMs       int64  `json:"duration_ms,omitempty"`
	ErrorType        string `json:"error_type,omitempty"`
	ErrorMessage     string `json:"error_message,omitempty"`
	Result           string `json:"result,omitempty"`
}

type AttemptResultSnapshot struct {
	StatusCode   int
	DurationMs   int64
	ErrorType    string
	ErrorMessage string
	Result       string
}
