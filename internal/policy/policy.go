// Package policy implements a small policy engine for TEE attestation
// evidence. It is built entirely from public concepts of how remote
// attestation works in general:
//
//   - A workload running in a TEE produces "evidence" (signed claims about
//     itself: measurements, signer identity, TCB version, debug mode, ...).
//   - A verifier checks that evidence against a "policy" that encodes what
//     the relying party trusts.
//
// This package deliberately does NOT implement any real quote parsing or
// cryptographic verification for a specific vendor's attestation format —
// it evaluates claim-based evidence against JSON policies, which is the
// clean, vendor-neutral core of any policy-based verifier.
package policy

import (
	"fmt"
	"sort"
	"strings"
)

// Policy is a JSON document describing what evidence is acceptable.
type Policy struct {
	ID             string            `json:"id"`
	RequiredClaims map[string]string `json:"required_claims,omitempty"`
	AllowedSigners []string          `json:"allowed_signers,omitempty"`
	MinTCBSVN      int               `json:"min_tcb_svn,omitempty"`
	DenyDebug      bool              `json:"deny_debug,omitempty"`
	CreatedAt      string            `json:"created_at,omitempty"`
}

// Evidence is the attestation evidence presented by a workload.
type Evidence struct {
	PolicyID string         `json:"policy_id"`
	Claims   map[string]any `json:"claims"`
}

// Verdict is the result of evaluating evidence against a policy.
type Verdict struct {
	Verdict string   `json:"verdict"` // "allow" or "deny"
	Reasons []string `json:"reasons"`
}

const (
	Allow = "allow"
	Deny  = "deny"
)

// Evaluate checks evidence against policy and returns a verdict with a
// human-readable reason for every failing check. Evaluation is deny-by-
// default: any failing check denies, and an unknown policy_id denies.
func Evaluate(p *Policy, ev Evidence) Verdict {
	v := Verdict{Reasons: []string{}}
	if p == nil {
		v.Verdict = Deny
		v.Reasons = append(v.Reasons, fmt.Sprintf("policy %q not found", ev.PolicyID))
		return v
	}

	deny := func(format string, args ...any) {
		v.Verdict = Deny
		v.Reasons = append(v.Reasons, fmt.Sprintf(format, args...))
	}

	// 1. Required claims: exact match on every key the policy pins.
	keys := make([]string, 0, len(p.RequiredClaims))
	for k := range p.RequiredClaims {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic reason order
	for _, k := range keys {
		got, ok := ev.Claims[k]
		if !ok {
			deny("missing required claim %q", k)
			continue
		}
		if fmt.Sprintf("%v", got) != p.RequiredClaims[k] {
			deny("claim %q mismatch: expected %q, got %q", k, p.RequiredClaims[k], fmt.Sprintf("%v", got))
		}
	}

	// 2. Signer allow-list (supply-chain pinning).
	if len(p.AllowedSigners) > 0 {
		signer := fmt.Sprintf("%v", ev.Claims["mrsigner"])
		if _, ok := ev.Claims["mrsigner"]; !ok {
			deny("missing required claim %q (needed for signer allow-list)", "mrsigner")
		} else {
			allowed := false
			for _, s := range p.AllowedSigners {
				if s == signer {
					allowed = true
					break
				}
			}
			if !allowed {
				deny("signer %q is not in allowed_signers %v", signer, p.AllowedSigners)
			}
		}
	}

	// 3. Minimum TCB security version (firmware freshness).
	if p.MinTCBSVN > 0 {
		raw, ok := ev.Claims["tcb_svn"]
		if !ok {
			deny("missing required claim %q (needed for TCB check)", "tcb_svn")
		} else {
			svn, ok := toInt(raw)
			if !ok {
				deny("claim %q is not an integer: %v", "tcb_svn", raw)
			} else if svn < p.MinTCBSVN {
				deny("tcb_svn %d is below minimum %d: platform firmware is out of date; update and re-attest", svn, p.MinTCBSVN)
			}
		}
	}

	// 4. Debug-mode denial (production workloads must not be debuggable).
	if p.DenyDebug {
		raw, ok := ev.Claims["debug_disabled"]
		if !ok {
			deny("missing required claim %q (needed for debug-mode check)", "debug_disabled")
		} else if !toBool(raw) {
			deny("debug mode is enabled: policy requires debug_disabled=true for production workloads")
		}
	}

	if v.Verdict == "" {
		v.Verdict = Allow
		v.Reasons = []string{"all policy checks passed"}
	}
	return v
}

// toInt coerces JSON numbers (and numeric strings) to int.
func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		if n == float64(int(n)) {
			return int(n), true
		}
	case int:
		return n, true
	case int64:
		return int(n), true
	case string:
		var i int
		if _, err := fmt.Sscanf(strings.TrimSpace(n), "%d", &i); err == nil {
			return i, true
		}
	}
	return 0, false
}

// toBool coerces JSON booleans (and "true"/"false" strings) to bool.
func toBool(v any) bool {
	switch b := v.(type) {
	case bool:
		return b
	case string:
		return strings.EqualFold(strings.TrimSpace(b), "true")
	}
	return false
}
