// Package server implements the REST API for the attestation policy gateway.
package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/PeaceXXX/attestation-policy-gateway/internal/metrics"
	"github.com/PeaceXXX/attestation-policy-gateway/internal/policy"
	"github.com/PeaceXXX/attestation-policy-gateway/internal/store"
)

// Server wires the policy engine, store, and metrics to HTTP handlers.
type Server struct {
	store   *store.Store
	metrics *metrics.Counters
	log     *slog.Logger
}

// New builds a Server.
func New(st *store.Store, m *metrics.Counters, log *slog.Logger) *Server {
	return &Server{store: st, metrics: m, log: log}
}

// Router returns the HTTP handler with all routes registered.
func (s *Server) Router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/verify", s.handleVerify)
	mux.HandleFunc("POST /v1/policies", s.handleCreatePolicy)
	mux.HandleFunc("GET /v1/policies", s.handleListPolicies)
	mux.HandleFunc("GET /v1/policies/{id}", s.handleGetPolicy)
	mux.HandleFunc("DELETE /v1/policies/{id}", s.handleDeletePolicy)
	mux.HandleFunc("GET /v1/audit", s.handleAudit)
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	return true
}

// handleVerify evaluates attestation evidence against a policy.
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	var ev policy.Evidence
	if !decodeJSON(w, r, &ev) {
		return
	}
	if ev.Claims == nil {
		ev.Claims = map[string]any{}
	}

	p, ok := s.store.GetPolicy(ev.PolicyID)
	var verdict policy.Verdict
	if !ok {
		verdict = policy.Evaluate(nil, ev)
	} else {
		verdict = policy.Evaluate(&p, ev)
	}

	s.metrics.Observe(verdict.Verdict)
	if err := s.store.AppendAudit(store.AuditEntry{
		PolicyID:  ev.PolicyID,
		Verdict:   verdict.Verdict,
		Reasons:   verdict.Reasons,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		s.log.Error("append audit entry", "error", err)
	}
	s.log.Info("verification",
		"policy_id", ev.PolicyID,
		"verdict", verdict.Verdict,
		"reasons", strings.Join(verdict.Reasons, "; "),
	)
	writeJSON(w, http.StatusOK, verdict)
}

// handleCreatePolicy creates a new policy document.
func (s *Server) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	var p policy.Policy
	if !decodeJSON(w, r, &p) {
		return
	}
	if err := s.store.CreatePolicy(p); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	stored, _ := s.store.GetPolicy(p.ID)
	s.log.Info("policy created", "policy_id", p.ID)
	writeJSON(w, http.StatusCreated, stored)
}

// handleListPolicies lists all policies.
func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"policies": s.store.ListPolicies()})
}

// handleGetPolicy returns one policy by ID.
func (s *Server) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, ok := s.store.GetPolicy(id)
	if !ok {
		writeError(w, http.StatusNotFound, "policy "+strconv.Quote(id)+" not found")
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// handleDeletePolicy deletes one policy by ID.
func (s *Server) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.store.DeletePolicy(id) {
		writeError(w, http.StatusNotFound, "policy "+strconv.Quote(id)+" not found")
		return
	}
	s.log.Info("policy deleted", "policy_id", id)
	w.WriteHeader(http.StatusNoContent)
}

// handleAudit returns recent audit entries, newest first. ?limit=N caps it.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit := 0
	if q := r.URL.Query().Get("limit"); q != "" {
		n, err := strconv.Atoi(q)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "limit must be a non-negative integer")
			return
		}
		limit = n
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": s.store.RecentAudit(limit)})
}

// handleMetrics exposes counters in Prometheus text format.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(s.metrics.Render()))
}

// handleHealth is a liveness probe.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
