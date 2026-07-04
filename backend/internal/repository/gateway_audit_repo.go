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
	return &gatewayAuditRepository{db: db}
}

func (r *gatewayAuditRepository) InsertAuditIndex(ctx context.Context, record *audit.IndexRecord) error {
	return r.BatchInsertAuditIndex(ctx, []*audit.IndexRecord{record})
}

func (r *gatewayAuditRepository) CleanupAuditRetention(ctx context.Context, cutoff time.Time) error {
	if r == nil || r.db == nil {
		return fmt.Errorf("nil gateway audit repository")
	}
	if cutoff.IsZero() {
		return nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
DELETE FROM admin_audit_access_logs
WHERE created_at < $1
   OR audit_id IN (
     SELECT audit_id
     FROM gateway_audit_index
     WHERE created_at < $1
   )`, cutoff); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM gateway_audit_index
WHERE created_at < $1`, cutoff); err != nil {
		return err
	}
	return tx.Commit()
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
	variants := buildGatewayAuditLookupVariants(requestID)
	if len(variants) == 0 {
		return nil, service.ErrGatewayAuditNotFound
	}

	var query strings.Builder
	query.WriteString(`
WITH variants(request_id, client_request_id, rank) AS (
  VALUES `)

	args := make([]any, 0, len(variants)*3+1)
	for i, variant := range variants {
		if i > 0 {
			query.WriteByte(',')
		}
		args = append(args, variant.RequestID, variant.ClientRequestID, variant.Rank)
		fmt.Fprintf(&query, "($%d::text,$%d::text,$%d::int)", len(args)-2, len(args)-1, len(args))
	}

	query.WriteString(`
)
SELECT
`)
	query.WriteString(gatewayAuditSelectColumnsSQL("i"))
	query.WriteString(`
FROM gateway_audit_index i
JOIN variants v ON (
  (v.request_id <> '' AND v.request_id = i.request_id)
  OR (v.client_request_id <> '' AND v.client_request_id = i.client_request_id)
)`)
	if apiKeyID > 0 {
		args = append(args, apiKeyID)
		fmt.Fprintf(&query, "\nWHERE i.api_key_id = $%d", len(args))
	}
	query.WriteString(`
ORDER BY v.rank ASC, i.created_at DESC, i.audit_id DESC
LIMIT 1`)

	row := r.db.QueryRowContext(ctx, query.String(), args...)
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
	candidates := buildGatewayAuditBatchLookupCandidates(keys, out)
	if len(candidates) == 0 {
		return out, nil
	}

	var query strings.Builder
	query.WriteString(`
WITH keys(input_request_id, input_api_key_id, lookup_request_id, lookup_client_request_id, rank) AS (
  VALUES `)
	args := make([]any, 0, len(candidates)*5)
	for i, candidate := range candidates {
		if i > 0 {
			query.WriteByte(',')
		}
		args = append(args,
			candidate.InputKey.RequestID,
			candidate.InputKey.APIKeyID,
			candidate.LookupRequestID,
			candidate.LookupClientRequestID,
			candidate.Rank,
		)
		fmt.Fprintf(&query, "($%d::text,$%d::bigint,$%d::text,$%d::text,$%d::int)", len(args)-4, len(args)-3, len(args)-2, len(args)-1, len(args))
	}
	query.WriteString(`
)
SELECT DISTINCT ON (k.input_request_id, k.input_api_key_id)
  k.input_request_id,
  k.input_api_key_id,
`)
	query.WriteString(gatewayAuditSelectColumnsSQL("i"))
	query.WriteString(`
FROM gateway_audit_index i
JOIN keys k ON k.input_api_key_id = i.api_key_id AND (
  (k.lookup_request_id <> '' AND k.lookup_request_id = i.request_id)
  OR (k.lookup_client_request_id <> '' AND k.lookup_client_request_id = i.client_request_id)
)
ORDER BY k.input_request_id, k.input_api_key_id, k.rank ASC, i.created_at DESC, i.audit_id DESC`)

	rows, err := r.db.QueryContext(ctx, query.String(), args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		key, item, err := scanGatewayAuditRowWithLookupKey(rows)
		if err != nil {
			return nil, err
		}
		if out[key] == nil {
			out[key] = item
		}
	}
	return out, rows.Err()
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
	return "\nSELECT\n" + gatewayAuditSelectColumnsSQL("i")
}

func gatewayAuditSelectColumnsSQL(alias string) string {
	alias = strings.TrimSpace(alias)
	if alias == "" {
		alias = "i"
	}
	return fmt.Sprintf(`  %s.audit_id,
  COALESCE(%s.request_id, ''),
  COALESCE(%s.client_request_id, ''),
  %s.user_id,
  %s.api_key_id,
  %s.account_id,
  %s.group_id,
  COALESCE(%s.platform, ''),
  COALESCE(%s.model, ''),
  COALESCE(%s.inbound_endpoint, ''),
  COALESCE(%s.upstream_endpoint, ''),
  COALESCE(%s.method, ''),
  COALESCE(%s.path, ''),
  COALESCE(%s.status_code, 0),
  COALESCE(%s.error_type, ''),
  COALESCE(%s.input_hash, ''),
  COALESCE(%s.output_hash, ''),
  COALESCE(%s.input_size, 0),
  COALESCE(%s.output_size, 0),
  %s.input_truncated,
  %s.output_truncated,
  COALESCE(%s.duration_ms, 0),
  COALESCE(%s.time_to_first_token_ms, 0),
  COALESCE(%s.attempt_count, 0),
  %s.has_failover,
  COALESCE(%s.first_upstream_status_code, 0),
  COALESCE(%s.final_upstream_status_code, 0),
  COALESCE(%s.capture_mode, ''),
  %s.sampled,
  COALESCE(%s.file_path, ''),
  %s.file_offset,
  %s.line_bytes,
  %s.created_at
`, alias, alias, alias, alias, alias, alias, alias, alias, alias, alias, alias, alias, alias, alias, alias, alias, alias, alias, alias, alias, alias, alias, alias, alias, alias, alias, alias, alias, alias, alias, alias, alias, alias)
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
	if err := scanGatewayAuditRowInto(row, nil, item); err != nil {
		return nil, err
	}
	return item, nil
}

func scanGatewayAuditRowWithLookupKey(row gatewayAuditScanner) (service.GatewayAuditRequestKey, *service.GatewayAuditIndex, error) {
	key := service.GatewayAuditRequestKey{}
	item := &service.GatewayAuditIndex{}
	if err := scanGatewayAuditRowInto(row, &key, item); err != nil {
		return service.GatewayAuditRequestKey{}, nil, err
	}
	return key, item, nil
}

func scanGatewayAuditRowInto(row gatewayAuditScanner, lookupKey *service.GatewayAuditRequestKey, item *service.GatewayAuditIndex) error {
	if item == nil {
		return fmt.Errorf("nil gateway audit index destination")
	}
	var userID, apiKeyID, accountID, groupID sql.NullInt64
	dest := make([]any, 0, 35)
	if lookupKey != nil {
		dest = append(dest, &lookupKey.RequestID, &lookupKey.APIKeyID)
	}
	dest = append(dest,
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
		&item.AttemptCount,
		&item.HasFailover,
		&item.FirstUpstreamStatusCode,
		&item.FinalUpstreamStatusCode,
		&item.CaptureMode,
		&item.Sampled,
		&item.FilePath,
		&item.FileOffset,
		&item.LineBytes,
		&item.CreatedAt,
	)
	if err := row.Scan(dest...); err != nil {
		return err
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
	return nil
}

type gatewayAuditLookupVariant struct {
	RequestID       string
	ClientRequestID string
	Rank            int
}

type gatewayAuditBatchLookupCandidate struct {
	InputKey              service.GatewayAuditRequestKey
	LookupRequestID       string
	LookupClientRequestID string
	Rank                  int
}

func buildGatewayAuditBatchLookupCandidates(keys []service.GatewayAuditRequestKey, out map[service.GatewayAuditRequestKey]*service.GatewayAuditIndex) []gatewayAuditBatchLookupCandidate {
	candidates := make([]gatewayAuditBatchLookupCandidate, 0, len(keys)*2)
	seen := make(map[string]struct{}, len(keys)*2)
	for _, key := range keys {
		key.RequestID = strings.TrimSpace(key.RequestID)
		if key.RequestID == "" || key.APIKeyID <= 0 {
			continue
		}
		if _, ok := out[key]; ok {
			// key already initialized in result map; still need lookup candidates only once.
		} else {
			out[key] = nil
		}
		for _, variant := range buildGatewayAuditLookupVariants(key.RequestID) {
			dedupeKey := fmt.Sprintf("%s|%d|%s|%s|%d", key.RequestID, key.APIKeyID, variant.RequestID, variant.ClientRequestID, variant.Rank)
			if _, ok := seen[dedupeKey]; ok {
				continue
			}
			seen[dedupeKey] = struct{}{}
			candidates = append(candidates, gatewayAuditBatchLookupCandidate{
				InputKey:              key,
				LookupRequestID:       variant.RequestID,
				LookupClientRequestID: variant.ClientRequestID,
				Rank:                  variant.Rank,
			})
		}
	}
	return candidates
}

func buildGatewayAuditLookupVariants(requestID string) []gatewayAuditLookupVariant {
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		return nil
	}
	variants := make([]gatewayAuditLookupVariant, 0, 2)
	seen := make(map[string]struct{}, 2)
	add := func(requestValue, clientRequestValue string) {
		requestValue = strings.TrimSpace(requestValue)
		clientRequestValue = strings.TrimSpace(clientRequestValue)
		if requestValue == "" && clientRequestValue == "" {
			return
		}
		key := requestValue + "\x00" + clientRequestValue
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		variants = append(variants, gatewayAuditLookupVariant{
			RequestID:       requestValue,
			ClientRequestID: clientRequestValue,
			Rank:            len(variants),
		})
	}

	switch {
	case strings.HasPrefix(requestID, "client:"):
		add("", strings.TrimSpace(strings.TrimPrefix(requestID, "client:")))
		add(requestID, "")
	case strings.HasPrefix(requestID, "local:"):
		add(strings.TrimSpace(strings.TrimPrefix(requestID, "local:")), "")
		add(requestID, "")
	case strings.HasPrefix(requestID, "generated:"):
		add(requestID, "")
	default:
		add(requestID, "")
		add("", requestID)
	}

	return variants
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
