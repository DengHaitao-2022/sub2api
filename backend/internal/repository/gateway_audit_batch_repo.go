package repository

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/audit"
)

const gatewayAuditIndexInsertColumns = `
  audit_id, request_id, client_request_id, user_id, api_key_id, account_id, group_id,
  platform, model, inbound_endpoint, upstream_endpoint, method, path, status_code, error_type,
  input_hash, output_hash, input_size, output_size, input_truncated, output_truncated,
  duration_ms, time_to_first_token_ms, attempt_count, has_failover,
  first_upstream_status_code, final_upstream_status_code,
  capture_mode, sampled, file_path, file_offset, line_bytes, created_at
`

const gatewayAuditIndexUpsertClause = `
ON CONFLICT (audit_id) DO UPDATE SET
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
  attempt_count = EXCLUDED.attempt_count,
  has_failover = EXCLUDED.has_failover,
  first_upstream_status_code = EXCLUDED.first_upstream_status_code,
  final_upstream_status_code = EXCLUDED.final_upstream_status_code,
  capture_mode = EXCLUDED.capture_mode,
  sampled = EXCLUDED.sampled,
  file_path = EXCLUDED.file_path,
  file_offset = EXCLUDED.file_offset,
  line_bytes = EXCLUDED.line_bytes,
  created_at = EXCLUDED.created_at`

func (r *gatewayAuditRepository) BatchInsertAuditIndex(ctx context.Context, records []*audit.IndexRecord) error {
	if r == nil || r.db == nil {
		return fmt.Errorf("nil gateway audit repository")
	}
	records = dedupeAuditIndexRecords(records)
	if len(records) == 0 {
		return nil
	}

	var query strings.Builder
	query.WriteString("INSERT INTO gateway_audit_index (")
	query.WriteString(gatewayAuditIndexInsertColumns)
	query.WriteString(") VALUES ")

	args := make([]any, 0, len(records)*33)
	now := time.Now()
	for i, record := range records {
		if i > 0 {
			query.WriteByte(',')
		}
		query.WriteByte('(')
		for col := 0; col < 33; col++ {
			if col > 0 {
				query.WriteByte(',')
			}
			fmt.Fprintf(&query, "$%d", len(args)+col+1)
		}
		query.WriteByte(')')

		createdAt := record.CreatedAt
		if createdAt.IsZero() {
			createdAt = now
		}
		args = append(args,
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
			record.AttemptCount,
			record.HasFailover,
			auditNullInt(record.FirstUpstreamStatusCode),
			auditNullInt(record.FinalUpstreamStatusCode),
			auditNullString(record.CaptureMode),
			record.Sampled,
			auditNullString(record.FilePath),
			record.FileOffset,
			record.LineBytes,
			createdAt,
		)
	}
	query.WriteString(gatewayAuditIndexUpsertClause)

	_, err := r.db.ExecContext(ctx, query.String(), args...)
	return err
}

func dedupeAuditIndexRecords(records []*audit.IndexRecord) []*audit.IndexRecord {
	if len(records) == 0 {
		return nil
	}
	out := make([]*audit.IndexRecord, 0, len(records))
	seen := make(map[string]int, len(records))
	for _, record := range records {
		if record == nil {
			continue
		}
		record.AuditID = strings.TrimSpace(record.AuditID)
		if record.AuditID == "" {
			continue
		}
		if idx, ok := seen[record.AuditID]; ok {
			out[idx] = record
			continue
		}
		seen[record.AuditID] = len(out)
		out = append(out, record)
	}
	return out
}
