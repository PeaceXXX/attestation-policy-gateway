package server

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PeaceXXX/attestation-policy-gateway/internal/metrics"
	"github.com/PeaceXXX/attestation-policy-gateway/internal/policy"
	"github.com/PeaceXXX/attestation-policy-gateway/internal/store"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	return New(st, &metrics.Counters{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func do(t *testing.T, s *Server, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		rdr = bytes.NewReader(data)
	}
	req := httptest.NewRequest(method, path, rdr)
	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, req)
	return rec
}

func TestPolicyCRUDHandlers(t *testing.T) {
	s := newTestServer(t)

	p := policy.Policy{
		ID:             "web",
		RequiredClaims: map[string]string{"mr_enclave": "abc"},
		AllowedSigners: []string{"s1"},
		MinTCBSVN:      5,
		DenyDebug:      true,
	}

	// Create.
	rec := do(t, s, "POST", "/v1/policies", p)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d: %s", rec.Code, rec.Body.String())
	}
	// Duplicate create -> 409.
	rec = do(t, s, "POST", "/v1/policies", p)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate create: got %d", rec.Code)
	}
	// List.
	rec = do(t, s, "GET", "/v1/policies", nil)
	var list struct {
		Policies []policy.Policy `json:"policies"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("list decode: %v", err)
	}
	if len(list.Policies) != 1 || list.Policies[0].ID != "web" {
		t.Fatalf("list: %v", list.Policies)
	}
	// Get.
	rec = do(t, s, "GET", "/v1/policies/web", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: got %d", rec.Code)
	}
	var got policy.Policy
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.MinTCBSVN != 5 {
		t.Fatalf("get returned wrong policy: %+v", got)
	}
	// Get missing -> 404.
	rec = do(t, s, "GET", "/v1/policies/nope", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get missing: got %d", rec.Code)
	}
	// Delete.
	rec = do(t, s, "DELETE", "/v1/policies/web", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: got %d", rec.Code)
	}
	// Delete missing -> 404.
	rec = do(t, s, "DELETE", "/v1/policies/web", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete missing: got %d", rec.Code)
	}
}

func TestVerifyHandler(t *testing.T) {
	s := newTestServer(t)
	p := policy.Policy{
		ID:             "prod",
		RequiredClaims: map[string]string{"mr_enclave": "abc", "issuer": "demo"},
		AllowedSigners: []string{"good-signer"},
		MinTCBSVN:      5,
		DenyDebug:      true,
	}
	if rec := do(t, s, "POST", "/v1/policies", p); rec.Code != http.StatusCreated {
		t.Fatalf("seed policy: %d", rec.Code)
	}

	pass := policy.Evidence{PolicyID: "prod", Claims: map[string]any{
		"mr_enclave": "abc", "mrsigner": "good-signer",
		"tcb_svn": float64(7), "debug_disabled": true, "issuer": "demo",
	}}
	rec := do(t, s, "POST", "/v1/verify", pass)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify: got %d: %s", rec.Code, rec.Body.String())
	}
	var v policy.Verdict
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if v.Verdict != policy.Allow {
		t.Fatalf("expected allow, got %v", v.Reasons)
	}

	fail := policy.Evidence{PolicyID: "prod", Claims: map[string]any{
		"mr_enclave": "abc", "mrsigner": "evil-signer",
		"tcb_svn": float64(2), "debug_disabled": false, "issuer": "demo",
	}}
	rec = do(t, s, "POST", "/v1/verify", fail)
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if v.Verdict != policy.Deny {
		t.Fatalf("expected deny, got allow")
	}
	joined := strings.Join(v.Reasons, " ")
	for _, want := range []string{"allowed_signers", "tcb_svn", "debug"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected reason mentioning %q in %q", want, joined)
		}
	}

	// Unknown policy -> deny.
	rec = do(t, s, "POST", "/v1/verify", policy.Evidence{PolicyID: "ghost", Claims: map[string]any{}})
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if v.Verdict != policy.Deny {
		t.Fatalf("expected deny for unknown policy")
	}

	// Malformed JSON -> 400.
	req := httptest.NewRequest("POST", "/v1/verify", strings.NewReader("{bad json"))
	rec2 := httptest.NewRecorder()
	s.Router().ServeHTTP(rec2, req)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("malformed JSON: got %d", rec2.Code)
	}
}

func TestAuditHandler(t *testing.T) {
	s := newTestServer(t)
	_ = do(t, s, "POST", "/v1/policies", policy.Policy{ID: "p"})
	_ = do(t, s, "POST", "/v1/verify", policy.Evidence{PolicyID: "p", Claims: map[string]any{}})
	_ = do(t, s, "POST", "/v1/verify", policy.Evidence{PolicyID: "p", Claims: map[string]any{}})

	rec := do(t, s, "GET", "/v1/audit?limit=1", nil)
	var out struct {
		Entries []store.AuditEntry `json:"entries"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out.Entries) != 1 {
		t.Fatalf("expected 1 entry with limit=1, got %d", len(out.Entries))
	}
	rec = do(t, s, "GET", "/v1/audit", nil)
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(out.Entries))
	}
	rec = do(t, s, "GET", "/v1/audit?limit=abc", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad limit: got %d", rec.Code)
	}
}

func TestMetricsHandler(t *testing.T) {
	s := newTestServer(t)
	_ = do(t, s, "POST", "/v1/policies", policy.Policy{ID: "p"})
	_ = do(t, s, "POST", "/v1/verify", policy.Evidence{PolicyID: "p", Claims: map[string]any{}})
	_ = do(t, s, "POST", "/v1/verify", policy.Evidence{PolicyID: "ghost", Claims: map[string]any{}})

	rec := do(t, s, "GET", "/metrics", nil)
	body := rec.Body.String()
	for _, want := range []string{
		"gateway_verifications_total 2",
		"gateway_allowed_total 1",
		"gateway_denied_total 1",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics missing %q:\n%s", want, body)
		}
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("unexpected content type %q", ct)
	}
}

func TestHealthz(t *testing.T) {
	s := newTestServer(t)
	rec := do(t, s, "GET", "/healthz", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz: got %d", rec.Code)
	}
}
