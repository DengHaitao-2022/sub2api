package handler

import (
	"errors"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/audit"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

func captureGatewayInput(c *gin.Context, protocol, endpoint, model string, stream bool, body []byte) {
	audit.CaptureInput(c, audit.InputSnapshot{
		Protocol:    protocol,
		Endpoint:    endpoint,
		Model:       model,
		Stream:      stream,
		Body:        body,
		ContentType: c.GetHeader("Content-Type"),
	})
}

func captureGatewayInputHash(c *gin.Context, protocol, endpoint, model string, stream bool, body []byte) {
	audit.CaptureInput(c, audit.InputSnapshot{
		Protocol:    protocol,
		Endpoint:    endpoint,
		Model:       model,
		Stream:      stream,
		Body:        body,
		ContentType: c.GetHeader("Content-Type"),
		CaptureMode: "hash",
	})
}

func setSelectedAccountContexts(c *gin.Context, account *service.Account) {
	if account == nil {
		return
	}
	setOpsSelectedAccount(c, account.ID, account.Platform)
	audit.MarkAccount(c, audit.AccountSnapshot{
		AccountID:        account.ID,
		AccountName:      account.Name,
		Platform:         account.Platform,
		UpstreamEndpoint: GetUpstreamEndpoint(c, account.Platform),
	})
}

func markGatewayAuditAttemptResult(c *gin.Context, statusCode int, durationMs int64, err error) {
	snapshot := audit.AttemptResultSnapshot{
		StatusCode: statusCode,
		DurationMs: durationMs,
	}
	if err != nil {
		snapshot.Result = "failed"
		snapshot.ErrorType = classifyGatewayAuditErrorType(statusCode, err)
		snapshot.ErrorMessage = strings.TrimSpace(err.Error())
		var failoverErr *service.UpstreamFailoverError
		if errors.As(err, &failoverErr) {
			snapshot.Result = "failover"
			if snapshot.StatusCode <= 0 {
				snapshot.StatusCode = failoverErr.StatusCode
			}
			if snapshot.ErrorType == "" {
				snapshot.ErrorType = classifyGatewayAuditStatus(failoverErr.StatusCode)
			}
		}
	} else {
		snapshot.Result = "completed"
		if snapshot.StatusCode <= 0 {
			snapshot.StatusCode = 200
		}
	}
	audit.MarkAttemptResult(c, snapshot)
}

func classifyGatewayAuditErrorType(statusCode int, err error) string {
	if statusCode > 0 {
		return classifyGatewayAuditStatus(statusCode)
	}
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "context canceled"), strings.Contains(msg, "client disconnected"), strings.Contains(msg, "broken pipe"):
		return "client_cancelled"
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline exceeded"):
		return "upstream_timeout"
	default:
		return "unknown"
	}
}

func classifyGatewayAuditStatus(statusCode int) string {
	switch {
	case statusCode == 401 || statusCode == 403:
		return "auth_failed"
	case statusCode == 408 || statusCode == 504:
		return "upstream_timeout"
	case statusCode == 413:
		return "request_too_large"
	case statusCode == 429:
		return "rate_limit"
	case statusCode >= 400 && statusCode < 500:
		return "upstream_4xx"
	case statusCode >= 500:
		return "upstream_5xx"
	default:
		return ""
	}
}
