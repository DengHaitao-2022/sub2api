package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/audit"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

var ErrGatewayAuditNotFound = infraerrors.NotFound("GATEWAY_AUDIT_NOT_FOUND", "gateway audit not found")

type GatewayAuditRepository interface {
	InsertAuditIndex(ctx context.Context, record *audit.IndexRecord) error
	ListGatewayAudit(ctx context.Context, filter *GatewayAuditFilter) (*GatewayAuditList, error)
	GetGatewayAuditIndex(ctx context.Context, auditID string) (*GatewayAuditIndex, error)
	GetGatewayAuditByRequest(ctx context.Context, requestID string, apiKeyID int64) (*GatewayAuditIndex, error)
	BatchFindGatewayAuditByRequest(ctx context.Context, keys []GatewayAuditRequestKey) (map[GatewayAuditRequestKey]*GatewayAuditIndex, error)
	GetGatewayAuditStats(ctx context.Context, filter *GatewayAuditFilter) (*GatewayAuditStats, error)
	InsertGatewayAuditAccessLog(ctx context.Context, log *GatewayAuditAccessLog) error
	ListGatewayAuditAccessLogs(ctx context.Context, auditID string, limit int) ([]*GatewayAuditAccessLogEntry, error)
	GetGatewayAuditHealth(ctx context.Context) (*GatewayAuditHealth, error)
}

type GatewayAuditService struct {
	repo GatewayAuditRepository
}

func NewGatewayAuditService(repo GatewayAuditRepository) *GatewayAuditService {
	return &GatewayAuditService{repo: repo}
}

type GatewayAuditFilter struct {
	Page     int
	PageSize int

	StartTime *time.Time
	EndTime   *time.Time

	RequestID        string
	ClientRequestID  string
	UserID           *int64
	APIKeyID         *int64
	AccountID        *int64
	GroupID          *int64
	Model            string
	Platform         string
	StatusCode       *int
	ErrorType        string
	Path             string
	InboundEndpoint  string
	UpstreamEndpoint string
	HasInput         *bool
	HasOutput        *bool
	OnlyErrors       bool
}

type GatewayAuditList struct {
	Items    []*GatewayAuditIndex
	Total    int64
	Page     int
	PageSize int
}

type GatewayAuditIndex struct {
	AuditID            string    `json:"audit_id"`
	RequestID          string    `json:"request_id,omitempty"`
	ClientRequestID    string    `json:"client_request_id,omitempty"`
	UserID             *int64    `json:"user_id,omitempty"`
	APIKeyID           *int64    `json:"api_key_id,omitempty"`
	AccountID          *int64    `json:"account_id,omitempty"`
	GroupID            *int64    `json:"group_id,omitempty"`
	Platform           string    `json:"platform,omitempty"`
	Model              string    `json:"model,omitempty"`
	InboundEndpoint    string    `json:"inbound_endpoint,omitempty"`
	UpstreamEndpoint   string    `json:"upstream_endpoint,omitempty"`
	Method             string    `json:"method,omitempty"`
	Path               string    `json:"path,omitempty"`
	StatusCode         int       `json:"status_code,omitempty"`
	ErrorType          string    `json:"error_type,omitempty"`
	InputHash          string    `json:"input_hash,omitempty"`
	OutputHash         string    `json:"output_hash,omitempty"`
	InputSize          int64     `json:"input_size"`
	OutputSize         int64     `json:"output_size"`
	InputTruncated     bool      `json:"input_truncated"`
	OutputTruncated    bool      `json:"output_truncated"`
	DurationMs         int64     `json:"duration_ms"`
	TimeToFirstTokenMs int64     `json:"time_to_first_token_ms"`
	CaptureMode        string    `json:"capture_mode,omitempty"`
	Sampled            bool      `json:"sampled"`
	FilePath           string    `json:"-"`
	FileOffset         int64     `json:"-"`
	LineBytes          int64     `json:"-"`
	CreatedAt          time.Time `json:"created_at"`
}

type GatewayAuditStats struct {
	Total           int64   `json:"total"`
	Success         int64   `json:"success"`
	Errors          int64   `json:"errors"`
	ErrorRate       float64 `json:"error_rate"`
	InputCaptured   int64   `json:"input_captured"`
	OutputCaptured  int64   `json:"output_captured"`
	InputTruncated  int64   `json:"input_truncated"`
	OutputTruncated int64   `json:"output_truncated"`
	AvgDurationMs   float64 `json:"avg_duration_ms"`
	MaxDurationMs   int64   `json:"max_duration_ms"`
	AvgFirstTokenMs float64 `json:"avg_first_token_ms"`
	MaxFirstTokenMs int64   `json:"max_first_token_ms"`
}

type GatewayAuditHealth struct {
	IndexedTotal        int64      `json:"indexed_total"`
	LastIndexedAt       *time.Time `json:"last_indexed_at,omitempty"`
	OldestIndexedAt     *time.Time `json:"oldest_indexed_at,omitempty"`
	Recent24h           int64      `json:"recent_24h"`
	Errors24h           int64      `json:"errors_24h"`
	LastJSONLFilePath   string     `json:"last_jsonl_file_path,omitempty"`
	LastJSONLFileExists bool       `json:"last_jsonl_file_exists"`
	LastJSONLFileSize   int64      `json:"last_jsonl_file_size,omitempty"`
}

type GatewayAuditDetail struct {
	Index *GatewayAuditIndex `json:"index"`
	Event *audit.Event       `json:"event,omitempty"`
}

type GatewayAuditRequestKey struct {
	RequestID string
	APIKeyID  int64
}

type GatewayAuditAccessLog struct {
	OperatorID   int64
	AuditID      string
	Action       string
	ViewedFields []string
	IPAddress    string
	UserAgent    string
}

type GatewayAuditAccessLogEntry struct {
	ID           int64     `json:"id"`
	OperatorID   int64     `json:"operator_id"`
	AuditID      string    `json:"audit_id"`
	Action       string    `json:"action"`
	ViewedFields []string  `json:"viewed_fields"`
	IPAddress    string    `json:"ip_address,omitempty"`
	UserAgent    string    `json:"user_agent,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

func (s *GatewayAuditService) List(ctx context.Context, filter *GatewayAuditFilter) (*GatewayAuditList, error) {
	if s == nil || s.repo == nil {
		return nil, fmt.Errorf("gateway audit service unavailable")
	}
	normalizeGatewayAuditFilter(filter)
	return s.repo.ListGatewayAudit(ctx, filter)
}

func (s *GatewayAuditService) Stats(ctx context.Context, filter *GatewayAuditFilter) (*GatewayAuditStats, error) {
	if s == nil || s.repo == nil {
		return nil, fmt.Errorf("gateway audit service unavailable")
	}
	normalizeGatewayAuditFilter(filter)
	return s.repo.GetGatewayAuditStats(ctx, filter)
}

func (s *GatewayAuditService) GetDetail(ctx context.Context, auditID string, access *GatewayAuditAccessLog) (*GatewayAuditDetail, error) {
	if s == nil || s.repo == nil {
		return nil, fmt.Errorf("gateway audit service unavailable")
	}
	auditID = strings.TrimSpace(auditID)
	if auditID == "" {
		return nil, ErrGatewayAuditNotFound
	}
	idx, err := s.repo.GetGatewayAuditIndex(ctx, auditID)
	if err != nil {
		return nil, err
	}
	event, err := readGatewayAuditEvent(idx)
	if err != nil {
		return nil, err
	}
	if access != nil && access.OperatorID > 0 {
		access.AuditID = idx.AuditID
		if strings.TrimSpace(access.Action) == "" {
			access.Action = "view_detail"
		}
		if len(access.ViewedFields) == 0 {
			access.ViewedFields = []string{"metadata", "input", "output"}
		}
		_ = s.repo.InsertGatewayAuditAccessLog(ctx, access)
	}
	return &GatewayAuditDetail{Index: idx, Event: event}, nil
}

func (s *GatewayAuditService) ExportJSONL(ctx context.Context, filter *GatewayAuditFilter, access GatewayAuditAccessLog) ([]byte, int, error) {
	if s == nil || s.repo == nil {
		return nil, 0, fmt.Errorf("gateway audit service unavailable")
	}
	if filter == nil {
		filter = &GatewayAuditFilter{}
	}
	normalizeGatewayAuditFilter(filter)
	if filter.Page <= 0 {
		filter.Page = 1
	}
	filter.PageSize = 200
	const maxExportItems = 5000
	var out strings.Builder
	exported := 0
	for exported < maxExportItems {
		list, err := s.repo.ListGatewayAudit(ctx, filter)
		if err != nil {
			return nil, exported, err
		}
		if len(list.Items) == 0 {
			break
		}
		for _, item := range list.Items {
			if item == nil {
				continue
			}
			event, err := readGatewayAuditEvent(item)
			if err != nil {
				continue
			}
			raw, err := json.Marshal(event)
			if err != nil {
				return nil, exported, err
			}
			out.Write(raw)
			out.WriteByte('\n')
			exported++
			if access.OperatorID > 0 {
				_ = s.repo.InsertGatewayAuditAccessLog(ctx, &GatewayAuditAccessLog{
					OperatorID:   access.OperatorID,
					AuditID:      item.AuditID,
					Action:       "export",
					ViewedFields: []string{"metadata", "input", "output"},
					IPAddress:    access.IPAddress,
					UserAgent:    access.UserAgent,
				})
			}
			if exported >= maxExportItems {
				break
			}
		}
		if int64(filter.Page*filter.PageSize) >= list.Total {
			break
		}
		filter.Page++
	}
	return []byte(out.String()), exported, nil
}

func (s *GatewayAuditService) ListAccessLogs(ctx context.Context, auditID string, limit int) ([]*GatewayAuditAccessLogEntry, error) {
	if s == nil || s.repo == nil {
		return nil, fmt.Errorf("gateway audit service unavailable")
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	return s.repo.ListGatewayAuditAccessLogs(ctx, strings.TrimSpace(auditID), limit)
}

func (s *GatewayAuditService) Health(ctx context.Context) (*GatewayAuditHealth, error) {
	if s == nil || s.repo == nil {
		return nil, fmt.Errorf("gateway audit service unavailable")
	}
	health, err := s.repo.GetGatewayAuditHealth(ctx)
	if err != nil {
		return nil, err
	}
	if health != nil && strings.TrimSpace(health.LastJSONLFilePath) != "" {
		if info, statErr := os.Stat(health.LastJSONLFilePath); statErr == nil {
			health.LastJSONLFileExists = true
			health.LastJSONLFileSize = info.Size()
		}
	}
	return health, nil
}

func (s *GatewayAuditService) GetByRequest(ctx context.Context, requestID string, apiKeyID int64) (*GatewayAuditIndex, error) {
	if s == nil || s.repo == nil {
		return nil, fmt.Errorf("gateway audit service unavailable")
	}
	return s.repo.GetGatewayAuditByRequest(ctx, strings.TrimSpace(requestID), apiKeyID)
}

func (s *GatewayAuditService) BatchFindByRequest(ctx context.Context, keys []GatewayAuditRequestKey) (map[GatewayAuditRequestKey]*GatewayAuditIndex, error) {
	if s == nil || s.repo == nil || len(keys) == 0 {
		return map[GatewayAuditRequestKey]*GatewayAuditIndex{}, nil
	}
	return s.repo.BatchFindGatewayAuditByRequest(ctx, keys)
}

func normalizeGatewayAuditFilter(filter *GatewayAuditFilter) {
	if filter == nil {
		return
	}
	if filter.Page <= 0 {
		filter.Page = 1
	}
	if filter.PageSize <= 0 {
		filter.PageSize = 50
	}
	if filter.PageSize > 200 {
		filter.PageSize = 200
	}
}

func readGatewayAuditEvent(idx *GatewayAuditIndex) (*audit.Event, error) {
	if idx == nil || strings.TrimSpace(idx.FilePath) == "" || idx.LineBytes <= 0 {
		return nil, ErrGatewayAuditNotFound
	}
	f, err := os.Open(idx.FilePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Seek(idx.FileOffset, io.SeekStart); err != nil {
		return nil, err
	}
	buf := make([]byte, idx.LineBytes)
	if _, err := io.ReadFull(f, buf); err != nil {
		return nil, err
	}
	buf = []byte(strings.TrimSpace(string(buf)))
	var event audit.Event
	if err := json.Unmarshal(buf, &event); err != nil {
		return nil, err
	}
	if event.AuditID != "" && event.AuditID != idx.AuditID {
		return nil, ErrGatewayAuditNotFound
	}
	return &event, nil
}
