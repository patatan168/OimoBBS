// 運用設定のHTMLとAPIへ認証・CSRF・CASを接続する。
package bootstrap

import (
	"io"
	"mime"
	"net/http"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"oimobbs/internal/webui"
	"strconv"
)

type operationsPage struct {
	State             AdminOperations
	CSRF, RequestID   string
	CacheLimitMiB     uint64
	GenerationWorkers int
}

// editableOperationSettings は手動で変更できる項目だけを受け付けるAPI境界。
// 保持容量・生成数は資源観測から決め、入力JSONに含まれた場合も拒否する。
type editableOperationSettings struct {
	Maintenance           PackMaintenanceConfig `json:"maintenance"`
	EgressBits            uint64                `json:"egress_budget_bits_per_second"`
	Reports               ReportPolicy          `json:"reports"`
	ReportIntervalMinutes int                   `json:"report_interval_minutes,omitempty"`
}

func (v OperationSettings) editable() editableOperationSettings {
	return editableOperationSettings{v.Maintenance, v.EgressBits, v.Reports, v.reportIntervalMinutes()}
}

// operationsResponse は保存形式に含まれる過去の手動資源値をAPIへ公開しない。
type operationsResponse struct {
	Settings    editableOperationSettings `json:"settings"`
	Revision    domain.U64                `json:"revision"`
	ReportBoard string                    `json:"report_board"`
}

func operationsAPI(v AdminOperations) operationsResponse {
	return operationsResponse{v.Settings.editable(), v.Revision, v.ReportBoard}
}

var operationsTemplate = webui.Template("operations")

func (h *adminHandler) operationsRoutes(w http.ResponseWriter, r *http.Request, s adminauth.Session) {
	const route = "/api/v1/operations"
	api := r.URL.Path == route
	if r.Method == "GET" {
		v, e := h.repo.adminOperations(s)
		if e != nil {
			h.failure(w, r, e)
			return
		}
		w.Header().Set("ETag", v.ETag())
		if api {
			w.Header().Set("X-CSRF-Token", s.CSRF(route))
			adminJSON(w, 200, map[string]any{"data": operationsAPI(v)})
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		cache := h.repo.feedCompression.Status()
		_ = executeAdminTemplate(w, w, operationsTemplate, operationsPage{State: v, CSRF: s.CSRF(route), RequestID: domain.NewID().String(), CacheLimitMiB: cache.Limit >> 20, GenerationWorkers: cache.Workers})
		return
	}
	if r.Method != "POST" {
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	var v OperationSettings
	var key, etag, csrf string
	if api {
		var e error
		csrf, _, e = singleRequestHeader(r.Header, "X-CSRF-Token")
		if e != nil || !s.CheckCSRF(route, csrf) {
			h.fail(w, r, 403, "CSRF_REJECTED")
			return
		}
		etag, _, e = singleRequestHeader(r.Header, "If-Match")
		if e != nil {
			h.fail(w, r, 400, "INVALID_REVISION")
			return
		}
		key, _, e = singleRequestHeader(r.Header, "Idempotency-Key")
		if e != nil {
			h.fail(w, r, 400, "INVALID_REQUEST_KEY")
			return
		}
		typ, _, e := singleRequestHeader(r.Header, "Content-Type")
		media, _, err := mime.ParseMediaType(typ)
		if e != nil || err != nil || media != "application/json" {
			h.fail(w, r, 415, "JSON_REQUIRED")
			return
		}
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<10))
		var input editableOperationSettings
		if e != nil || strictjson.Decode(raw, &input) != nil {
			h.fail(w, r, 400, "INVALID_JSON")
			return
		}
		v = OperationSettings{Maintenance: input.Maintenance, EgressBits: input.EgressBits, Reports: input.Reports, ReportIntervalMinutes: input.ReportIntervalMinutes}
	} else {
		f, e := adminForm(w, r, 8<<10, "csrf", "revision", "request_id", "maintenance_enabled", "interval_seconds", "max_threads", "max_seconds", "egress_mbps", "window_minutes", "quorum", "stop_minutes", "report_interval_minutes")
		if e != nil {
			h.fail(w, r, 400, "INVALID_FORM")
			return
		}
		csrf, etag, key = f.Get("csrf"), f.Get("revision"), f.Get("request_id")
		if !s.CheckCSRF(route, csrf) {
			h.fail(w, r, 403, "CSRF_REJECTED")
			return
		}
		values := map[string]int{}
		for _, name := range []string{"interval_seconds", "max_threads", "max_seconds", "egress_mbps", "window_minutes", "quorum", "stop_minutes"} {
			n, e := strconv.Atoi(f.Get(name))
			if e != nil || n < 0 || n > 1_048_576 {
				h.fail(w, r, 422, "INVALID_OPERATIONS")
				return
			}
			values[name] = n
		}
		enabled := f.Get("maintenance_enabled")
		if enabled != "true" && enabled != "false" {
			h.fail(w, r, 422, "INVALID_OPERATIONS")
			return
		}
		interval := h.repo.operations().reportIntervalMinutes()
		if raw := f.Get("report_interval_minutes"); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n < 1 || n > 1440 {
				h.fail(w, r, 422, "INVALID_OPERATIONS")
				return
			}
			interval = n
		}
		v = OperationSettings{ReportIntervalMinutes: interval, Maintenance: PackMaintenanceConfig{enabled == "true", values["max_seconds"], values["interval_seconds"], values["max_threads"]}, EgressBits: uint64(values["egress_mbps"]) * 1_000_000, Reports: ReportPolicy{values["window_minutes"] * 60, values["quorum"], values["stop_minutes"] * 60}}
	}
	result, e := h.repo.updateOperations(s, v, etag, key)
	if e != nil {
		h.failure(w, r, e)
		return
	}
	w.Header().Set("ETag", result.ETag())
	if api {
		adminJSON(w, 200, map[string]any{"data": operationsAPI(result)})
		return
	}
	http.Redirect(w, r, "/operations", 303)
}

// 以下は管理フォームの表示単位への変換。保存単位はbyte・bit/s・秒のまま保つ。
func (v OperationSettings) EgressMbps() uint64 { return v.EgressBits / 1_000_000 }
func (p ReportPolicy) WindowMinutes() int      { return p.WindowSeconds / 60 }
func (p ReportPolicy) StopMinutes() int        { return p.StopSeconds / 60 }
