package store

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PeaceXXX/attestation-policy-gateway/internal/policy"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestPolicyCRUD(t *testing.T) {
	s := newTestStore(t)
	p := policy.Policy{ID: "p1", MinTCBSVN: 3, DenyDebug: true}

	if err := s.CreatePolicy(p); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	if err := s.CreatePolicy(p); err == nil {
		t.Fatalf("expected duplicate create to fail")
	}
	if err := s.CreatePolicy(policy.Policy{}); err == nil {
		t.Fatalf("expected empty-id create to fail")
	}

	got, ok := s.GetPolicy("p1")
	if !ok || got.MinTCBSVN != 3 || !got.DenyDebug {
		t.Fatalf("GetPolicy returned %+v, ok=%v", got, ok)
	}
	if _, ok := s.GetPolicy("missing"); ok {
		t.Fatalf("expected missing policy to be absent")
	}

	list := s.ListPolicies()
	if len(list) != 1 || list[0].ID != "p1" {
		t.Fatalf("ListPolicies returned %v", list)
	}

	if !s.DeletePolicy("p1") {
		t.Fatalf("DeletePolicy should return true")
	}
	if s.DeletePolicy("p1") {
		t.Fatalf("second DeletePolicy should return false")
	}
	if _, ok := s.GetPolicy("p1"); ok {
		t.Fatalf("policy should be gone after delete")
	}
}

func TestPolicyPersistence(t *testing.T) {
	dir := t.TempDir()
	s1, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s1.CreatePolicy(policy.Policy{ID: "persist-me", MinTCBSVN: 9}); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}

	s2, err := New(dir)
	if err != nil {
		t.Fatalf("New (reload): %v", err)
	}
	got, ok := s2.GetPolicy("persist-me")
	if !ok || got.MinTCBSVN != 9 {
		t.Fatalf("policy not persisted: %+v ok=%v", got, ok)
	}
	if _, err := os.Stat(filepath.Join(dir, "policies.json")); err != nil {
		t.Fatalf("policies.json missing: %v", err)
	}
}

func TestAuditAppendAndRecent(t *testing.T) {
	s := newTestStore(t)
	for i := 0; i < 5; i++ {
		verdict := policy.Allow
		if i%2 == 0 {
			verdict = policy.Deny
		}
		if err := s.AppendAudit(AuditEntry{PolicyID: "p1", Verdict: verdict, Reasons: []string{"r"}}); err != nil {
			t.Fatalf("AppendAudit: %v", err)
		}
	}
	recent := s.RecentAudit(2)
	if len(recent) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(recent))
	}
	if recent[0].Verdict != policy.Deny || recent[1].Verdict != policy.Allow {
		t.Fatalf("expected newest-first ordering, got %v", recent)
	}
	all := s.RecentAudit(0)
	if len(all) != 5 {
		t.Fatalf("expected all 5 entries, got %d", len(all))
	}
}

func TestAuditPersistence(t *testing.T) {
	dir := t.TempDir()
	s1, _ := New(dir)
	_ = s1.AppendAudit(AuditEntry{PolicyID: "p1", Verdict: policy.Deny, Reasons: []string{"bad tcb"}})

	s2, err := New(dir)
	if err != nil {
		t.Fatalf("New (reload): %v", err)
	}
	all := s2.RecentAudit(0)
	if len(all) != 1 || all[0].Verdict != policy.Deny {
		t.Fatalf("audit not persisted: %v", all)
	}
	if _, err := os.Stat(filepath.Join(dir, "audit.jsonl")); err != nil {
		t.Fatalf("audit.jsonl missing: %v", err)
	}
}
