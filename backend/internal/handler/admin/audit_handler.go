package admin

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/pkg/timezone"
	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

type AuditHandler struct {
	auditService *service.GatewayAuditService
}

func NewAuditHandler(auditService *service.GatewayAuditService) *AuditHandler {
	return &AuditHandler{auditService: auditService}
}

// List returns indexed gateway audit records.
// GET /api/v1/admin/audit
func (h *AuditHandler) List(c *gin.Context) {
	if h.auditService == nil {
		response.Error(c, http.StatusServiceUnavailable, "Audit service not available")
		return
	}
	filter, err := parseGatewayAuditFilter(c)
	if err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	result, err := h.auditService.List(c.Request.Context(), filter)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Paginated(c, result.Items, result.Total, result.Page, result.PageSize)
}

// Stats returns aggregate troubleshooting counters for indexed gateway audits.
// GET /api/v1/admin/audit/stats
func (h *AuditHandler) Stats(c *gin.Context) {
	if h.auditService == nil {
		response.Error(c, http.StatusServiceUnavailable, "Audit service not available")
		return
	}
	filter, err := parseGatewayAuditFilter(c)
	if err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	stats, err := h.auditService.Stats(c.Request.Context(), filter)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, stats)
}

// Get returns the full gateway audit event by indexed JSONL offset.
// GET /api/v1/admin/audit/:audit_id
func (h *AuditHandler) Get(c *gin.Context) {
	if h.auditService == nil {
		response.Error(c, http.StatusServiceUnavailable, "Audit service not available")
		return
	}
	subject, ok := middleware.GetAuthSubjectFromContext(c)
	if !ok || subject.UserID <= 0 {
		response.Unauthorized(c, "Unauthorized")
		return
	}
	detail, err := h.auditService.GetDetail(c.Request.Context(), c.Param("audit_id"), &service.GatewayAuditAccessLog{
		OperatorID: subject.UserID,
		IPAddress:  c.ClientIP(),
		UserAgent:  c.GetHeader("User-Agent"),
	})
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, detail)
}

// ByRequest returns the latest audit index for a usage request_id/api_key_id pair.
// GET /api/v1/admin/audit/by-request?request_id=xxx&api_key_id=123
func (h *AuditHandler) ByRequest(c *gin.Context) {
	if h.auditService == nil {
		response.Error(c, http.StatusServiceUnavailable, "Audit service not available")
		return
	}
	requestID := strings.TrimSpace(c.Query("request_id"))
	if requestID == "" {
		response.BadRequest(c, "request_id is required")
		return
	}
	var apiKeyID int64
	if raw := strings.TrimSpace(c.Query("api_key_id")); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed <= 0 {
			response.BadRequest(c, "Invalid api_key_id")
			return
		}
		apiKeyID = parsed
	}
	item, err := h.auditService.GetByRequest(c.Request.Context(), requestID, apiKeyID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, item)
}

// Export streams matching full audit events as JSONL.
// POST /api/v1/admin/audit/export
func (h *AuditHandler) Export(c *gin.Context) {
	if h.auditService == nil {
		response.Error(c, http.StatusServiceUnavailable, "Audit service not available")
		return
	}
	subject, ok := middleware.GetAuthSubjectFromContext(c)
	if !ok || subject.UserID <= 0 {
		response.Unauthorized(c, "Unauthorized")
		return
	}
	filter, err := parseGatewayAuditFilter(c)
	if err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	raw, count, err := h.auditService.ExportJSONL(c.Request.Context(), filter, service.GatewayAuditAccessLog{
		OperatorID: subject.UserID,
		IPAddress:  c.ClientIP(),
		UserAgent:  c.GetHeader("User-Agent"),
	})
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	filename := fmt.Sprintf("gateway_audit_%s.jsonl", time.Now().Format("20060102_150405"))
	c.Header("Content-Disposition", `attachment; filename="`+filename+`"`)
	c.Header("X-Audit-Export-Count", strconv.Itoa(count))
	c.Data(http.StatusOK, "application/x-ndjson; charset=utf-8", raw)
}

// Health returns index and latest JSONL health for admin monitoring.
// GET /api/v1/admin/audit/health
func (h *AuditHandler) Health(c *gin.Context) {
	if h.auditService == nil {
		response.Error(c, http.StatusServiceUnavailable, "Audit service not available")
		return
	}
	health, err := h.auditService.Health(c.Request.Context())
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, health)
}

// AccessLogs returns who viewed or exported audit records.
// GET /api/v1/admin/audit/access-logs
func (h *AuditHandler) AccessLogs(c *gin.Context) {
	if h.auditService == nil {
		response.Error(c, http.StatusServiceUnavailable, "Audit service not available")
		return
	}
	limit := 50
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			response.BadRequest(c, "Invalid limit")
			return
		}
		limit = parsed
	}
	items, err := h.auditService.ListAccessLogs(c.Request.Context(), c.Query("audit_id"), limit)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, items)
}

func parseGatewayAuditFilter(c *gin.Context) (*service.GatewayAuditFilter, error) {
	page, pageSize := response.ParsePagination(c)
	filter := &service.GatewayAuditFilter{
		Page:             page,
		PageSize:         pageSize,
		RequestID:        strings.TrimSpace(c.Query("request_id")),
		ClientRequestID:  strings.TrimSpace(c.Query("client_request_id")),
		Model:            strings.TrimSpace(c.Query("model")),
		Platform:         strings.TrimSpace(c.Query("platform")),
		ErrorType:        strings.TrimSpace(c.Query("error_type")),
		Path:             strings.TrimSpace(c.Query("path")),
		InboundEndpoint:  strings.TrimSpace(c.Query("inbound_endpoint")),
		UpstreamEndpoint: strings.TrimSpace(c.Query("upstream_endpoint")),
	}
	if c.Query("only_errors") != "" {
		value, err := strconv.ParseBool(c.Query("only_errors"))
		if err != nil {
			return nil, err
		}
		filter.OnlyErrors = value
	}
	var err error
	if filter.StartTime, err = parseAuditQueryTime(c, "start_date", true); err != nil {
		return nil, err
	}
	if filter.EndTime, err = parseAuditQueryTime(c, "end_date", false); err != nil {
		return nil, err
	}
	if filter.UserID, err = parseAuditInt64Ptr(c.Query("user_id")); err != nil {
		return nil, err
	}
	if filter.APIKeyID, err = parseAuditInt64Ptr(c.Query("api_key_id")); err != nil {
		return nil, err
	}
	if filter.AccountID, err = parseAuditInt64Ptr(c.Query("account_id")); err != nil {
		return nil, err
	}
	if filter.GroupID, err = parseAuditInt64Ptr(c.Query("group_id")); err != nil {
		return nil, err
	}
	if filter.StatusCode, err = parseAuditIntPtr(c.Query("status_code")); err != nil {
		return nil, err
	}
	if filter.HasInput, err = parseAuditBoolPtr(c.Query("has_input")); err != nil {
		return nil, err
	}
	if filter.HasOutput, err = parseAuditBoolPtr(c.Query("has_output")); err != nil {
		return nil, err
	}
	return filter, nil
}

func parseAuditQueryTime(c *gin.Context, key string, start bool) (*time.Time, error) {
	raw := strings.TrimSpace(c.Query(key))
	if raw == "" {
		return nil, nil
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return &t, nil
	}
	t, err := timezone.ParseInUserLocation("2006-01-02", raw, c.Query("timezone"))
	if err != nil {
		return nil, err
	}
	if !start {
		t = t.AddDate(0, 0, 1)
	}
	return &t, nil
}

func parseAuditInt64Ptr(raw string) (*int64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return nil, strconv.ErrSyntax
	}
	return &value, nil
}

func parseAuditIntPtr(raw string) (*int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return nil, strconv.ErrSyntax
	}
	return &value, nil
}

func parseAuditBoolPtr(raw string) (*bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return nil, err
	}
	return &value, nil
}
