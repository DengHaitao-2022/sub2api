package repository

import (
	"context"
	"database/sql/driver"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Wei-Shaw/sub2api/internal/audit"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

func TestGatewayAuditRepositoryCleanupAuditRetention(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	cutoff := time.Date(2026, 6, 26, 0, 0, 0, 0, time.UTC)
	repo := &gatewayAuditRepository{db: db}

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM admin_audit_access_logs
WHERE created_at < $1
   OR audit_id IN (
     SELECT audit_id
     FROM gateway_audit_index
     WHERE created_at < $1
   )`)).
		WithArgs(cutoff).
		WillReturnResult(sqlmock.NewResult(0, 3))
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM gateway_audit_index
WHERE created_at < $1`)).
		WithArgs(cutoff).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectCommit()

	if err := repo.CleanupAuditRetention(context.Background(), cutoff); err != nil {
		t.Fatalf("CleanupAuditRetention: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestGatewayAuditRepositoryBatchInsertAuditIndex(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := &gatewayAuditRepository{db: db}
	mock.ExpectExec(`(?s)INSERT INTO gateway_audit_index \(.*\) VALUES \([^)]*\),\([^)]*\)\s+ON CONFLICT \(audit_id\) DO UPDATE SET`).
		WillReturnResult(sqlmock.NewResult(0, 2))

	err = repo.BatchInsertAuditIndex(context.Background(), []*audit.IndexRecord{
		{
			AuditID:     "aud_batch_repo_1",
			RequestID:   "req_1",
			APIKeyID:    10,
			StatusCode:  200,
			FilePath:    "/tmp/audit-2026-06-29.jsonl",
			FileOffset:  0,
			LineBytes:   100,
			CreatedAt:   time.Date(2026, 6, 29, 10, 0, 0, 0, time.UTC),
			CaptureMode: "preview/preview",
			Sampled:     true,
		},
		{
			AuditID:     "aud_batch_repo_2",
			RequestID:   "req_2",
			APIKeyID:    11,
			StatusCode:  500,
			ErrorType:   "upstream",
			FilePath:    "/tmp/audit-2026-06-29.jsonl",
			FileOffset:  100,
			LineBytes:   120,
			CreatedAt:   time.Date(2026, 6, 29, 10, 1, 0, 0, time.UTC),
			CaptureMode: "preview/preview",
			Sampled:     true,
		},
	})
	if err != nil {
		t.Fatalf("BatchInsertAuditIndex: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}

	if got := len(dedupeAuditIndexRecords([]*audit.IndexRecord{{AuditID: "x"}, {AuditID: " x "}})); got != 1 {
		t.Fatalf("dedupe records = %d, want 1", got)
	}
	if !strings.Contains(gatewayAuditIndexUpsertClause, "ON CONFLICT (audit_id) DO UPDATE") {
		t.Fatal("batch upsert clause must keep audit_id conflict update")
	}
}

func TestBuildGatewayAuditLookupVariants(t *testing.T) {
	tests := []struct {
		name      string
		requestID string
		want      []gatewayAuditLookupVariant
	}{
		{
			name:      "client prefixed usage request id falls back to client_request_id",
			requestID: "client:client-stable-123",
			want: []gatewayAuditLookupVariant{
				{RequestID: "", ClientRequestID: "client-stable-123", Rank: 0},
				{RequestID: "client:client-stable-123", ClientRequestID: "", Rank: 1},
			},
		},
		{
			name:      "local prefixed usage request id falls back to audit request_id",
			requestID: "local:req-local-456",
			want: []gatewayAuditLookupVariant{
				{RequestID: "req-local-456", ClientRequestID: "", Rank: 0},
				{RequestID: "local:req-local-456", ClientRequestID: "", Rank: 1},
			},
		},
		{
			name:      "plain request id checks request_id then client_request_id",
			requestID: "resp_upstream_789",
			want: []gatewayAuditLookupVariant{
				{RequestID: "resp_upstream_789", ClientRequestID: "", Rank: 0},
				{RequestID: "", ClientRequestID: "resp_upstream_789", Rank: 1},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildGatewayAuditLookupVariants(tt.requestID)
			if len(got) != len(tt.want) {
				t.Fatalf("len(variants) = %d, want %d", len(got), len(tt.want))
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("variant[%d] = %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestGatewayAuditRepositoryGetGatewayAuditByRequest_ClientPrefixedUsageID(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := &gatewayAuditRepository{db: db}
	mock.ExpectQuery(`(?s)WITH variants\(request_id, client_request_id, rank\) AS .*client_request_id = i.client_request_id.*ORDER BY v.rank ASC, i.created_at DESC, i.audit_id DESC\s+LIMIT 1`).
		WillReturnRows(sqlmock.NewRows(gatewayAuditQueryColumns()).
			AddRow(gatewayAuditRowValues(
				"aud_lookup_client_1",
				"srv-req-1",
				"client-stable-123",
				int64(1001),
				int64(42),
				int64(2001),
				int64(3001),
				time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC),
			)...))

	item, err := repo.GetGatewayAuditByRequest(context.Background(), "client:client-stable-123", 42)
	if err != nil {
		t.Fatalf("GetGatewayAuditByRequest: %v", err)
	}
	if item == nil {
		t.Fatal("expected audit item, got nil")
	}
	if item.AuditID != "aud_lookup_client_1" {
		t.Fatalf("AuditID = %q, want %q", item.AuditID, "aud_lookup_client_1")
	}
	if item.ClientRequestID != "client-stable-123" {
		t.Fatalf("ClientRequestID = %q, want %q", item.ClientRequestID, "client-stable-123")
	}
	if item.APIKeyID == nil || *item.APIKeyID != 42 {
		t.Fatalf("APIKeyID = %+v, want 42", item.APIKeyID)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestGatewayAuditRepositoryBatchFindGatewayAuditByRequest_ResolvesUsageRequestPrefixes(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	repo := &gatewayAuditRepository{db: db}
	mock.ExpectQuery(`(?s)WITH keys\(input_request_id, input_api_key_id, lookup_request_id, lookup_client_request_id, rank\) AS .*SELECT DISTINCT ON \(k.input_request_id, k.input_api_key_id\).*`).
		WillReturnRows(sqlmock.NewRows(gatewayAuditLookupQueryColumns()).
			AddRow(gatewayAuditLookupRowValues(
				"client:client-stable-123",
				int64(42),
				"aud_lookup_batch_client",
				"srv-req-client",
				"client-stable-123",
				int64(1001),
				int64(42),
				int64(2001),
				int64(3001),
				time.Date(2026, 7, 1, 10, 5, 0, 0, time.UTC),
			)...).
			AddRow(gatewayAuditLookupRowValues(
				"local:req-local-456",
				int64(77),
				"aud_lookup_batch_local",
				"req-local-456",
				"",
				int64(1002),
				int64(77),
				int64(2002),
				int64(3002),
				time.Date(2026, 7, 1, 10, 6, 0, 0, time.UTC),
			)...))

	keys := []service.GatewayAuditRequestKey{
		{RequestID: "client:client-stable-123", APIKeyID: 42},
		{RequestID: "local:req-local-456", APIKeyID: 77},
	}
	out, err := repo.BatchFindGatewayAuditByRequest(context.Background(), keys)
	if err != nil {
		t.Fatalf("BatchFindGatewayAuditByRequest: %v", err)
	}

	clientKey := service.GatewayAuditRequestKey{RequestID: "client:client-stable-123", APIKeyID: 42}
	clientItem := out[clientKey]
	if clientItem == nil {
		t.Fatalf("expected batch lookup result for %+v", clientKey)
	}
	if clientItem.AuditID != "aud_lookup_batch_client" {
		t.Fatalf("client AuditID = %q, want %q", clientItem.AuditID, "aud_lookup_batch_client")
	}
	if clientItem.ClientRequestID != "client-stable-123" {
		t.Fatalf("client ClientRequestID = %q, want %q", clientItem.ClientRequestID, "client-stable-123")
	}

	localKey := service.GatewayAuditRequestKey{RequestID: "local:req-local-456", APIKeyID: 77}
	localItem := out[localKey]
	if localItem == nil {
		t.Fatalf("expected batch lookup result for %+v", localKey)
	}
	if localItem.AuditID != "aud_lookup_batch_local" {
		t.Fatalf("local AuditID = %q, want %q", localItem.AuditID, "aud_lookup_batch_local")
	}
	if localItem.RequestID != "req-local-456" {
		t.Fatalf("local RequestID = %q, want %q", localItem.RequestID, "req-local-456")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func gatewayAuditQueryColumns() []string {
	return []string{
		"audit_id",
		"request_id",
		"client_request_id",
		"user_id",
		"api_key_id",
		"account_id",
		"group_id",
		"platform",
		"model",
		"inbound_endpoint",
		"upstream_endpoint",
		"method",
		"path",
		"status_code",
		"error_type",
		"input_hash",
		"output_hash",
		"input_size",
		"output_size",
		"input_truncated",
		"output_truncated",
		"duration_ms",
		"time_to_first_token_ms",
		"attempt_count",
		"has_failover",
		"first_upstream_status_code",
		"final_upstream_status_code",
		"capture_mode",
		"sampled",
		"file_path",
		"file_offset",
		"line_bytes",
		"created_at",
	}
}

func gatewayAuditLookupQueryColumns() []string {
	return append([]string{"input_request_id", "input_api_key_id"}, gatewayAuditQueryColumns()...)
}

func gatewayAuditLookupRowValues(inputRequestID string, inputAPIKeyID int64, auditID, requestID, clientRequestID string, userID, apiKeyID, accountID, groupID int64, createdAt time.Time) []driver.Value {
	values := []driver.Value{inputRequestID, inputAPIKeyID}
	return append(values, gatewayAuditRowValues(auditID, requestID, clientRequestID, userID, apiKeyID, accountID, groupID, createdAt)...)
}

func gatewayAuditRowValues(auditID, requestID, clientRequestID string, userID, apiKeyID, accountID, groupID int64, createdAt time.Time) []driver.Value {
	return []driver.Value{
		auditID,
		requestID,
		clientRequestID,
		userID,
		apiKeyID,
		accountID,
		groupID,
		"claude",
		"claude-sonnet-4",
		"messages",
		"/v1/messages",
		"POST",
		"/v1/messages",
		200,
		"",
		"input-hash",
		"output-hash",
		int64(123),
		int64(456),
		false,
		false,
		int64(789),
		int64(45),
		1,
		false,
		200,
		200,
		"preview/preview",
		true,
		"/tmp/audit-2026-07-01.jsonl",
		int64(0),
		int64(321),
		createdAt,
	}
}
