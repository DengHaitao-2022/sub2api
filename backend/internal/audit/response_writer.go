package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type ResponseWriter struct {
	gin.ResponseWriter

	statusCode   int
	bodySize     int64
	preview      bytes.Buffer
	hash         hash.Hash
	firstWrite   bool
	firstWriteAt time.Time
	maxCapture   int64
}

func NewResponseWriter(inner gin.ResponseWriter, maxCaptureBytes int64) *ResponseWriter {
	if maxCaptureBytes < 0 {
		maxCaptureBytes = 0
	}
	return &ResponseWriter{
		ResponseWriter: inner,
		hash:           sha256.New(),
		maxCapture:     maxCaptureBytes,
	}
}

func (w *ResponseWriter) WriteHeader(code int) {
	if w.statusCode == 0 {
		w.statusCode = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *ResponseWriter) Write(data []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	if !w.firstWrite {
		w.firstWrite = true
		w.firstWriteAt = time.Now()
	}
	_, _ = w.hash.Write(data)
	w.bodySize += int64(len(data))
	w.capturePreview(data)
	return w.ResponseWriter.Write(data)
}

func (w *ResponseWriter) WriteString(data string) (int, error) {
	return w.Write([]byte(data))
}

func (w *ResponseWriter) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(responseWriterOnly{w: w}, r)
}

func (w *ResponseWriter) StatusCode() int {
	if w.statusCode > 0 {
		return w.statusCode
	}
	if w.ResponseWriter != nil && w.ResponseWriter.Status() > 0 {
		return w.ResponseWriter.Status()
	}
	return http.StatusOK
}

func (w *ResponseWriter) FirstWriteAt() time.Time {
	if w == nil {
		return time.Time{}
	}
	return w.firstWriteAt
}

type responseWriterOnly struct {
	w *ResponseWriter
}

func (w responseWriterOnly) Write(data []byte) (int, error) {
	return w.w.Write(data)
}

func (w *ResponseWriter) SizeBytes() int64 {
	return w.bodySize
}

func (w *ResponseWriter) PreviewBytes() []byte {
	return w.preview.Bytes()
}

func (w *ResponseWriter) SHA256Hex() string {
	if w.hash == nil {
		sum := sha256.Sum256(nil)
		return hex.EncodeToString(sum[:])
	}
	return hex.EncodeToString(w.hash.Sum(nil))
}

func (w *ResponseWriter) Truncated() bool {
	return w.maxCapture > 0 && w.bodySize > w.maxCapture
}

func (w *ResponseWriter) capturePreview(data []byte) {
	if w.maxCapture <= 0 || len(data) == 0 {
		return
	}
	remain := w.maxCapture - int64(w.preview.Len())
	if remain <= 0 {
		return
	}
	if int64(len(data)) > remain {
		w.preview.Write(data[:remain])
		return
	}
	w.preview.Write(data)
}
