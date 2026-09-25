// Package store provides persistence for policies and the append-only
// audit log. Storage is in-memory for speed plus JSON file snapshots for
// durability — no external database, no cgo.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/PeaceXXX/attestation-policy-gateway/internal/policy"
)

// AuditEntry records one verification decision. The log is append-only:
// entries are never edited or deleted, which is what makes it a credible
// audit trail.
type AuditEntry struct {
	Timestamp string   `json:"timestamp"`
	PolicyID  string   `json:"policy_id"`
	Verdict   string   `json:"verdict"`
	Reasons   []string `json:"reasons"`
}

// Store holds policies and audit entries with file-backed persistence.
type Store struct {
	mu       sync.RWMutex
	policies map[string]policy.Policy
	audit    []AuditEntry
	dataDir  string
}

// New creates a Store, loading existing state from dataDir if present.
func New(dataDir string) (*Store, error) {
	s := &Store{
		policies: make(map[string]policy.Policy),
		dataDir:  dataDir,
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) policiesPath() string { return filepath.Join(s.dataDir, "policies.json") }
func (s *Store) auditPath() string    { return filepath.Join(s.dataDir, "audit.jsonl") }

// load restores policies and audit history from disk.
func (s *Store) load() error {
	if data, err := os.ReadFile(s.policiesPath()); err == nil {
		var ps []policy.Policy
		if err := json.Unmarshal(data, &ps); err != nil {
			return fmt.Errorf("parse policies.json: %w", err)
		}
		for _, p := range ps {
			s.policies[p.ID] = p
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read policies.json: %w", err)
	}

	if data, err := os.ReadFile(s.auditPath()); err == nil {
		for _, line := range splitLines(data) {
			var e AuditEntry
			if err := json.Unmarshal(line, &e); err != nil {
				return fmt.Errorf("parse audit.jsonl: %w", err)
			}
			s.audit = append(s.audit, e)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read audit.jsonl: %w", err)
	}
	return nil
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	for _, l := range split(data, '\n') {
		if len(trimSpace(l)) > 0 {
			lines = append(lines, l)
		}
	}
	return lines
}

func split(b []byte, sep byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == sep {
			out = append(out, b[start:i])
			start = i + 1
		}
	}
	return append(out, b[start:])
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t' || b[0] == '\r') {
		b = b[1:]
	}
	for len(b) > 0 && (b[len(b)-1] == ' ' || b[len(b)-1] == '\t' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

// savePolicies writes the full policy set atomically (write temp + rename).
func (s *Store) savePolicies() error {
	ps := make([]policy.Policy, 0, len(s.policies))
	for _, p := range s.policies {
		ps = append(ps, p)
	}
	data, err := json.MarshalIndent(ps, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.policiesPath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.policiesPath())
}

// CreatePolicy adds a policy; IDs must be unique and non-empty.
func (s *Store) CreatePolicy(p policy.Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.ID == "" {
		return fmt.Errorf("policy id is required")
	}
	if _, exists := s.policies[p.ID]; exists {
		return fmt.Errorf("policy %q already exists", p.ID)
	}
	if p.CreatedAt == "" {
		p.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	s.policies[p.ID] = p
	return s.savePolicies()
}

// GetPolicy returns a policy by ID.
func (s *Store) GetPolicy(id string) (policy.Policy, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.policies[id]
	return p, ok
}

// ListPolicies returns all policies in ID order.
func (s *Store) ListPolicies() []policy.Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ps := make([]policy.Policy, 0, len(s.policies))
	for _, p := range s.policies {
		ps = append(ps, p)
	}
	sortPolicies(ps)
	return ps
}

func sortPolicies(ps []policy.Policy) {
	for i := 1; i < len(ps); i++ {
		for j := i; j > 0 && ps[j].ID < ps[j-1].ID; j-- {
			ps[j], ps[j-1] = ps[j-1], ps[j]
		}
	}
}

// DeletePolicy removes a policy by ID.
func (s *Store) DeletePolicy(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.policies[id]; !ok {
		return false
	}
	delete(s.policies, id)
	_ = s.savePolicies()
	return true
}

// AppendAudit records a verification decision to memory and the JSONL file.
func (s *Store) AppendAudit(e AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.Timestamp == "" {
		e.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	s.audit = append(s.audit, e)
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(s.auditPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(data, '\n'))
	return err
}

// RecentAudit returns the most recent n audit entries (newest first).
// n <= 0 means all entries.
func (s *Store) RecentAudit(n int) []AuditEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AuditEntry, 0, len(s.audit))
	for i := len(s.audit) - 1; i >= 0; i-- {
		out = append(out, s.audit[i])
		if n > 0 && len(out) >= n {
			break
		}
	}
	return out
}
