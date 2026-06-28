package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/audit"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/lib/pq"
)

type gatewayAuditRepository struct {
	db *sql.DB
}

func NewGatewayAuditRepository(db *sql.DB) service.GatewayAuditRepository {
	repo := &gatewayAuditRepository{db: db}
	audit.SetIndexWriter(repo)
	return repo
}

func (r *gatewayAuditRepository) InsertAuditIndex(ctx context.Context, record *audit.IndexRecord) error {
	if r == nil || r.db == nil {
		return fmt.Errorf("nil gateway audit repository")
	}
	if record == nil || strings.TrimSpace(record.AuditID) == "" {
		return nil
	}
	createdAt := record.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now()
	}
	_, err := r.db.ExecContext(ctx, `
INSERT INTO gateway_audit_index (
  audit_id, request_id, client_request_id, user_id, api_key_id, account_id, group_id,
  platform, model, inbound_endpoint, upstream_endpoint, method, path, status_code, error_type,
  input_hash, output_hash, input_size, output_size, input_truncated, output_truncated,
  duration_ms, time_to_first_token_ms, capture_mode, sampled, file_path, file_offset, line_bytes, created_at
) VALUES (
  $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29
) ON CONFLICT (audit_id) DO UPDATE SET
  request_id = EXCLUDED.request_id,
  client_request_id = EXCLUDED.client_request_id,
  user_id = EXCLUDED.user_id,
  api_key_id = EXCLUDED.api_key_id,
  account_id = EXCLUDED.account_id,
  group_id = EXCLUDED.group_id,
  platform = EXCLUDED.platform,
  model = EXCLUDED.model,
  inbound_endpoint = EXCLUDED.inbound_endpoint,
  upstream_endpoint = EXCLUDED.upstream_endpoint,
  method = EXCLUDED.method,
  path = EXCLUDED.path,
  status_code = EXCLUDED.status_code,
  error_type = EXCLUDED.error_type,
  input_hash = EXCLUDED.input_hash,
  output_hash = EXCLUDED.output_hash,
  input_size = EXCLUDED.input_size,
  output_size = EXCLUDED.output_size,
  input_truncated = EXCLUDED.input_truncated,
  output_truncated = EXCLUDED.output_truncated,
  duration_ms = EXCLUDED.duration_ms,
  time_to_first_token_ms = EXCLUDED.time_to_first_token_ms,
  capture_mode = EXCLUDED.capture_mode,
  sampled = EXCLUDED.sampled,
  file_path = EXCLUDED.file_path,
  file_offset = EXCLUDED.file_offset,
  line_bytes = EXCLUDED.line_bytes,
  created_at = EXCLUDED.created_at`,
		record.AuditID,
		auditNullString(record.RequestID),
		auditNullString(record.ClientRequestID),
		auditNullInt64(record.UserID),
		auditNullInt64(record.APIKeyID),
		auditNullInt64(record.AccountID),
		auditNullInt64(record.GroupID),
		auditNullString(record.Platform),
		auditNullString(record.Model),
		auditNullString(record.InboundEndpoint),
		auditNullString(record.UpstreamEndpoint),
		auditNullString(record.Method),
		auditNullString(record.Path),
		auditNullInt(record.StatusCode),
		auditNullString(record.ErrorType),
		auditNullString(record.InputHash),
		auditNullString(record.OutputHash),
		record.InputSize,
		record.OutputSize,
		record.InputTruncated,
		record.OutputTruncated,
		record.DurationMs,
		record.TimeToFirstTokenMs,
		auditNullString(record.CaptureMode),
		record.Sampled,
		auditNullString(record.FilePath),
		record.FileOffset,
		record.LineBytes,
		createdAt,
	)
	return err
}

func (r *gatewayAuditRepository) GetGatewayAuditStats(ctx context.Context, filter *service.GatewayAuditFilter) (*service.GatewayAuditStats, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("nil gateway audit repository")
	}
	if filter == nil {
		filter = &service.GatewayAuditFilter{}
	}
	where, args := buildGatewayAuditWhere(filter)
	row := r.db.QueryRowContext(ctx, `
SELECT
  COUNT(*)::bigint,
  COUNT(*) FILTER (WHERE COALESCE(i.status_code, 0) > 0 AND i.status_code < 400)::bigint,
  COUNT(*) FILTER (WHERE COALESCE(i.status_code, 0) >= 400)::bigint,
  COUNT(*) FILTER (WHERE COALESCE(i.input_size, 0) > 0)::bigint,
  COUNT(*) FILTER (WHERE COALESCE(i.output_size, 0) > 0)::bigint,
  COUNT(*) FILTER (WHERE i.input_truncated)::bigint,
  COUNT(*) FILTER (WHERE i.output_truncated)::bigint,
  COALESCE(AVG(NULLIF(i.duration_ms, 0)), 0)::float8,
  COALESCE(MAX(i.duration_ms), 0)::bigint,
  COALESCE(AVG(NULLIF(i.time_to_first_token_ms, 0)), 0)::float8,
  COALESCE(MAX(i.time_to_first_token_ms), 0)::bigint
FROM gateway_audit_index i
`+where, args...)
	stats := &service.GatewayAuditStats{}
	if err := row.Scan(
		&stats.Total,
		&stats.Success,
		&stats.Errors,
		&stats.InputCaptured,
		&stats.OutputCaptured,
		&stats.InputTruncated,
		&stats.OutputTruncated,
		&stats.AvgDurationMs,
		&stats.MaxDurationMs,
		&stats.AvgFirstTokenMs,
		&stats.MaxFirstTokenMs,
	); err != nil {
		return nil, err
	}
	if stats.Total > 0 {
		stats.ErrorRate = float64(stats.Errors) / float64(stats.Total)
	}
	return stats, nil
}

func (r *gatewayAuditRepository) ListGatewayAudit(ctx context.Context, filter *service.GatewayAuditFilter) (*service.GatewayAuditList, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("nil gateway audit repository")
	}
	if filter == nil {
		filter = &service.GatewayAuditFilter{Page: 1, PageSize: 50}
	}
	where, args := buildGatewayAuditWhere(filter)
	var total int64
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM gateway_audit_index i "+where, args...).Scan(&total); err != nil {
		return nil, err
	}
	page, pageSize := filter.Page, filter.PageSize
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 50
	}
	if pageSize > 200 {
		pageSize = 200
	}
	offset := (page - 1) * pageSize
	queryArgs := append(append([]any{}, args...), pageSize, offset)
	rows, err := r.db.QueryContext(ctx, gatewayAuditSelectSQL()+`
FROM gateway_audit_index i
`+where+`
ORDER BY i.created_at DESC, i.audit_id DESC
LIMIT $`+fmt.Sprint(len(args)+1)+` OFFSET $`+fmt.Sprint(len(args)+2), queryArgs...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	items, err := scanGatewayAuditRows(rows)
	if err != nil {
		return nil, err
	}
	return &service.GatewayAuditList{Items: items, Total: total, Page: page, PageSize: pageSize}, nil
}

func (r *gatewayAuditRepository) GetGatewayAuditIndex(ctx context.Context, auditID string) (*service.GatewayAuditIndex, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("nil gateway audit repository")
	}
	row := r.db.QueryRowContext(ctx, gatewayAuditSelectSQL()+`
FROM gateway_audit_index i
WHERE i.audit_id = $1`, strings.TrimSpace(auditID))
	item, err := scanGatewayAuditRow(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, service.ErrGatewayAuditNotFound
		}
		return nil, err
	}
	return item, nil
}

func (r *gatewayAuditRepository) GetGatewayAuditByRequest(ctx context.Context, requestID string, apiKeyID int64) (*service.GatewayAuditIndex, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("nil gateway audit repository")
	}
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		return nil, service.ErrGatewayAuditNotFound
	}
	args := []any{requestID}
	where := "WHERE i.request_id = $1"
	if apiKeyID > 0 {
		args = append(args, apiKeyID)
		where += " AND i.api_key_id = $2"
	}
	row := r.db.QueryRowContext(ctx, gatewayAuditSelectSQL()+`
FROM gateway_audit_index i
`+where+`
ORDER BY i.created_at DESC
LIMIT 1`, args...)
	item, err := scanGatewayAuditRow(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, service.ErrGatewayAuditNotFound
		}
		return nil, err
	}
	return item, nil
}

func (r *gatewayAuditRepository) BatchFindGatewayAuditByRequest(ctx context.Context, keys []service.GatewayAuditRequestKey) (map[service.GatewayAuditRequestKey]*service.GatewayAuditIndex, error) {
	out := make(map[service.GatewayAuditRequestKey]*service.GatewayAuditIndex, len(keys))
	if r == nil || r.db == nil || len(keys) == 0 {
		return out, nil
	}
	values := make([]string, 0, len(keys))
	args := make([]any, 0, len(keys)*2)
	for _, key := range keys {
		key.RequestID = strings.TrimSpace(key.RequestID)
		if key.RequestID == "" || key.APIKeyID <= 0 {
			continue
		}
		if _, ok := out[key]; ok {
			continue
		}
		out[key] = nil
		args = append(args, key.RequestID, key.APIKeyID)
		values = append(values, fmt.Sprintf("($%d::text,$%d::bigint)", len(args)-1, len(args)))
	}
	if len(values) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `
WITH keys(request_id, api_key_id) AS (
  VALUES `+strings.Join(values, ",")+`
)
`+gatewayAuditSelectSQL()+`
FROM gateway_audit_index i
JOIN keys k ON k.request_id = i.request_id AND k.api_key_id = i.api_key_id
ORDER BY i.request_id, i.api_key_id, i.created_at DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	items, err := scanGatewayAuditRows(rows)
	if err != nil {
		return nil, err
	}
	for _, item := range items {
		if item == nil || item.RequestID == "" || item.APIKeyID == nil {
			continue
		}
		key := service.GatewayAuditRequestKey{RequestID: item.RequestID, APIKeyID: *item.APIKeyID}
		if out[key] == nil {
			out[key] = item
		}
	}
	return out, nil
}

func (r *gatewayAuditRepository) InsertGatewayAuditAccessLog(ctx context.Context, log *service.GatewayAuditAccessLog) error {
	if r == nil || r.db == nil || log == nil || log.OperatorID <= 0 || strings.TrimSpace(log.AuditID) == "" {
		return nil
	}
	_, err := r.db.ExecContext(ctx, `
INSERT INTO admin_audit_access_logs (
  operator_id, audit_id, action, viewed_fields, ip_address, user_agent
) VALUES ($1,$2,$3,$4,NULLIF($5,'')::inet,$6)`,
		log.OperatorID,
		strings.TrimSpace(log.AuditID),
		auditStringDefault(log.Action, "view_detail"),
		pq.Array(log.ViewedFields),
		strings.TrimSpace(log.IPAddress),
		auditNullString(log.UserAgent),
	)
	return err
}

func (r *gatewayAuditRepository) ListGatewayAuditAccessLogs(ctx context.Context, auditID string, limit int) ([]*service.GatewayAuditAccessLogEntry, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("nil gateway audit repository")
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	args := []any{limit}
	where := ""
	if auditID = strings.TrimSpace(auditID); auditID != "" {
		args = append(args, auditID)
		where = "WHERE audit_id = $2"
	}
	rows, err := r.db.QueryContext(ctx, `
SELECT
  id,
  operator_id,
  audit_id,
  action,
  viewed_fields,
  COALESCE(ip_address::text, ''),
  COALESCE(user_agent, ''),
  created_at
FROM admin_audit_access_logs
`+where+`
ORDER BY created_at DESC, id DESC
LIMIT $1`, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	items := make([]*service.GatewayAuditAccessLogEntry, 0)
	for rows.Next() {
		item := &service.GatewayAuditAccessLogEntry{}
		if err := rows.Scan(
			&item.ID,
			&item.OperatorID,
			&item.AuditID,
			&item.Action,
			pq.Array(&item.ViewedFields),
			&item.IPAddress,
			&item.UserAgent,
			&item.CreatedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *gatewayAuditRepository) GetGatewayAuditHealth(ctx context.Context) (*service.GatewayAuditHealth, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("nil gateway audit repository")
	}
	health := &service.GatewayAuditHealth{}
	var lastAt, oldestAt sql.NullTime
	var lastPath sql.NullString
	if err := r.db.QueryRowContext(ctx, `
SELECT
  COUNT(*)::bigint,
  MAX(created_at),
  MIN(created_at),
  COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours')::bigint,
  COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours' AND COALESCE(status_code, 0) >= 400)::bigint
FROM gateway_audit_index`).Scan(
		&health.IndexedTotal,
		&lastAt,
		&oldestAt,
		&health.Recent24h,
		&health.Errors24h,
	); err != nil {
		return nil, err
	}
	if lastAt.Valid {
		health.LastIndexedAt = &lastAt.Time
	}
	if oldestAt.Valid {
		health.OldestIndexedAt = &oldestAt.Time
	}
	if err := r.db.QueryRowContext(ctx, `
SELECT file_path
FROM gateway_audit_index
WHERE file_path IS NOT NULL AND file_path <> ''
ORDER BY created_at DESC
LIMIT 1`).Scan(&lastPath); err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	if lastPath.Valid {
		health.LastJSONLFilePath = lastPath.String
	}
	return health, nil
}

func buildGatewayAuditWhere(filter *service.GatewayAuditFilter) (string, []any) {
	parts := []string{"1=1"}
	args := make([]any, 0, 16)
	add := func(clause string, value any) {
		args = append(args, value)
		parts = append(parts, fmt.Sprintf(clause, len(args)))
	}
	if filter.StartTime != nil {
		add("i.created_at >= $%d", *filter.StartTime)
	}
	if filter.EndTime != nil {
		add("i.created_at < $%d", *filter.EndTime)
	}
	if v := strings.TrimSpace(filter.RequestID); v != "" {
		add("i.request_id = $%d", v)
	}
	if v := strings.TrimSpace(filter.ClientRequestID); v != "" {
		add("i.client_request_id = $%d", v)
	}
	if filter.UserID != nil && *filter.UserID > 0 {
		add("i.user_id = $%d", *filter.UserID)
	}
	if filter.APIKeyID != nil && *filter.APIKeyID > 0 {
		add("i.api_key_id = $%d", *filter.APIKeyID)
	}
	if filter.AccountID != nil && *filter.AccountID > 0 {
		add("i.account_id = $%d", *filter.AccountID)
	}
	if filter.GroupID != nil && *filter.GroupID > 0 {
		add("i.group_id = $%d", *filter.GroupID)
	}
	if v := strings.TrimSpace(filter.Model); v != "" {
		add("i.model = $%d", v)
	}
	if v := strings.TrimSpace(filter.Platform); v != "" {
		add("i.platform = $%d", v)
	}
	if filter.StatusCode != nil && *filter.StatusCode > 0 {
		add("i.status_code = $%d", *filter.StatusCode)
	}
	if v := strings.TrimSpace(filter.ErrorType); v != "" {
		add("i.error_type = $%d", v)
	}
	if v := strings.TrimSpace(filter.Path); v != "" {
		add("i.path = $%d", v)
	}
	if v := strings.TrimSpace(filter.InboundEndpoint); v != "" {
		add("i.inbound_endpoint = $%d", v)
	}
	if v := strings.TrimSpace(filter.UpstreamEndpoint); v != "" {
		add("i.upstream_endpoint = $%d", v)
	}
	if filter.HasInput != nil {
		if *filter.HasInput {
			parts = append(parts, "COALESCE(i.input_size, 0) > 0")
		} else {
			parts = append(parts, "COALESCE(i.input_size, 0) = 0")
		}
	}
	if filter.HasOutput != nil {
		if *filter.HasOutput {
			parts = append(parts, "COALESCE(i.output_size, 0) > 0")
		} else {
			parts = append(parts, "COALESCE(i.output_size, 0) = 0")
		}
	}
	if filter.OnlyErrors {
		parts = append(parts, "COALESCE(i.status_code, 0) >= 400")
	}
	return "WHERE " + strings.Join(parts, " AND "), args
}

func gatewayAuditSelectSQL() string {
	return `
SELECT
  i.audit_id,
  COALESCE(i.request_id, ''),
  COALESCE(i.client_request_id, ''),
  i.user_id,
  i.api_key_id,
  i.account_id,
  i.group_id,
  COALESCE(i.platform, ''),
  COALESCE(i.model, ''),
  COALESCE(i.inbound_endpoint, ''),
  COALESCE(i.upstream_endpoint, ''),
  COALESCE(i.method, ''),
  COALESCE(i.path, ''),
  COALESCE(i.status_code, 0),
  COALESCE(i.error_type, ''),
  COALESCE(i.input_hash, ''),
  COALESCE(i.output_hash, ''),
  COALESCE(i.input_size, 0),
  COALESCE(i.output_size, 0),
  i.input_truncated,
  i.output_truncated,
  COALESCE(i.duration_ms, 0),
  COALESCE(i.time_to_first_token_ms, 0),
  COALESCE(i.capture_mode, ''),
  i.sampled,
  COALESCE(i.file_path, ''),
  i.file_offset,
  i.line_bytes,
  i.created_at
`
}

type gatewayAuditScanner interface {
	Scan(dest ...any) error
}

func scanGatewayAuditRows(rows *sql.Rows) ([]*service.GatewayAuditIndex, error) {
	items := make([]*service.GatewayAuditIndex, 0)
	for rows.Next() {
		item, err := scanGatewayAuditRow(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func scanGatewayAuditRow(row gatewayAuditScanner) (*service.GatewayAuditIndex, error) {
	item := &service.GatewayAuditIndex{}
	var userID, apiKeyID, accountID, groupID sql.NullInt64
	if err := row.Scan(
		&item.AuditID,
		&item.RequestID,
		&item.ClientRequestID,
		&userID,
		&apiKeyID,
		&accountID,
		&groupID,
		&item.Platform,
		&item.Model,
		&item.InboundEndpoint,
		&item.UpstreamEndpoint,
		&item.Method,
		&item.Path,
		&item.StatusCode,
		&item.ErrorType,
		&item.InputHash,
		&item.OutputHash,
		&item.InputSize,
		&item.OutputSize,
		&item.InputTruncated,
		&item.OutputTruncated,
		&item.DurationMs,
		&item.TimeToFirstTokenMs,
		&item.CaptureMode,
		&item.Sampled,
		&item.FilePath,
		&item.FileOffset,
		&item.LineBytes,
		&item.CreatedAt,
	); err != nil {
		return nil, err
	}
	if userID.Valid {
		item.UserID = &userID.Int64
	}
	if apiKeyID.Valid {
		item.APIKeyID = &apiKeyID.Int64
	}
	if accountID.Valid {
		item.AccountID = &accountID.Int64
	}
	if groupID.Valid {
		item.GroupID = &groupID.Int64
	}
	return item, nil
}

func auditNullString(value string) sql.NullString {
	value = strings.TrimSpace(value)
	return sql.NullString{String: value, Valid: value != ""}
}

func auditNullInt64(value int64) sql.NullInt64 {
	return sql.NullInt64{Int64: value, Valid: value > 0}
}

func auditNullInt(value int) sql.NullInt64 {
	return sql.NullInt64{Int64: int64(value), Valid: value > 0}
}

func auditStringDefault(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}
