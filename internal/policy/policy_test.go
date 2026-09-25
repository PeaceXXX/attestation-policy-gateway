package policy

import (
	"strings"
	"testing"
)

func testPolicy() *Policy {
	return &Policy{
		ID: "prod-web",
		RequiredClaims: map[string]string{
			"mr_enclave": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
			"issuer":     "demo-attestation-service",
		},
		AllowedSigners: []string{"signer-alice", "signer-bob"},
		MinTCBSVN:      5,
		DenyDebug:      true,
	}
}

func goodClaims() map[string]any {
	return map[string]any{
		"mr_enclave":     "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
		"mrsigner":       "signer-alice",
		"tcb_svn":        float64(7),
		"debug_disabled": true,
		"issuer":         "demo-attestation-service",
	}
}

func TestEvaluate_Allow(t *testing.T) {
	v := Evaluate(testPolicy(), Evidence{PolicyID: "prod-web", Claims: goodClaims()})
	if v.Verdict != Allow {
		t.Fatalf("expected allow, got %q: %v", v.Verdict, v.Reasons)
	}
}

func TestEvaluate_UnknownPolicy(t *testing.T) {
	v := Evaluate(nil, Evidence{PolicyID: "nope", Claims: goodClaims()})
	if v.Verdict != Deny {
		t.Fatalf("expected deny for unknown policy, got %q", v.Verdict)
	}
	if !strings.Contains(v.Reasons[0], "not found") {
		t.Fatalf("expected 'not found' reason, got %v", v.Reasons)
	}
}

func TestEvaluate_MissingClaim(t *testing.T) {
	claims := goodClaims()
	delete(claims, "mr_enclave")
	v := Evaluate(testPolicy(), Evidence{PolicyID: "prod-web", Claims: claims})
	if v.Verdict != Deny {
		t.Fatalf("expected deny, got %q", v.Verdict)
	}
	if !strings.Contains(strings.Join(v.Reasons, " "), "missing required claim \"mr_enclave\"") {
		t.Fatalf("expected missing-claim reason, got %v", v.Reasons)
	}
}

func TestEvaluate_ClaimMismatch(t *testing.T) {
	claims := goodClaims()
	claims["mr_enclave"] = "deadbeef"
	v := Evaluate(testPolicy(), Evidence{PolicyID: "prod-web", Claims: claims})
	if v.Verdict != Deny {
		t.Fatalf("expected deny, got %q", v.Verdict)
	}
	if !strings.Contains(strings.Join(v.Reasons, " "), "mismatch") {
		t.Fatalf("expected mismatch reason, got %v", v.Reasons)
	}
}

func TestEvaluate_DebugEnabled(t *testing.T) {
	claims := goodClaims()
	claims["debug_disabled"] = false
	v := Evaluate(testPolicy(), Evidence{PolicyID: "prod-web", Claims: claims})
	if v.Verdict != Deny {
		t.Fatalf("expected deny when debug enabled, got %q", v.Verdict)
	}
	if !strings.Contains(strings.Join(v.Reasons, " "), "debug") {
		t.Fatalf("expected debug reason, got %v", v.Reasons)
	}
}

func TestEvaluate_DebugAllowedWhenPolicyPermits(t *testing.T) {
	p := testPolicy()
	p.DenyDebug = false
	claims := goodClaims()
	claims["debug_disabled"] = false
	v := Evaluate(p, Evidence{PolicyID: "prod-web", Claims: claims})
	if v.Verdict != Allow {
		t.Fatalf("expected allow when deny_debug=false, got %q: %v", v.Verdict, v.Reasons)
	}
}

func TestEvaluate_TCBTooLow(t *testing.T) {
	for _, raw := range []any{float64(4), 4, "4"} {
		claims := goodClaims()
		claims["tcb_svn"] = raw
		v := Evaluate(testPolicy(), Evidence{PolicyID: "prod-web", Claims: claims})
		if v.Verdict != Deny {
			t.Fatalf("expected deny for tcb_svn=%v, got %q", raw, v.Verdict)
		}
		if !strings.Contains(strings.Join(v.Reasons, " "), "tcb_svn") {
			t.Fatalf("expected tcb_svn reason, got %v", v.Reasons)
		}
	}
}

func TestEvaluate_TCBAtMinimum(t *testing.T) {
	claims := goodClaims()
	claims["tcb_svn"] = float64(5)
	v := Evaluate(testPolicy(), Evidence{PolicyID: "prod-web", Claims: claims})
	if v.Verdict != Allow {
		t.Fatalf("expected allow at minimum tcb_svn, got %q: %v", v.Verdict, v.Reasons)
	}
}

func TestEvaluate_SignerNotAllowed(t *testing.T) {
	claims := goodClaims()
	claims["mrsigner"] = "signer-mallory"
	v := Evaluate(testPolicy(), Evidence{PolicyID: "prod-web", Claims: claims})
	if v.Verdict != Deny {
		t.Fatalf("expected deny for unlisted signer, got %q", v.Verdict)
	}
	if !strings.Contains(strings.Join(v.Reasons, " "), "allowed_signers") {
		t.Fatalf("expected signer reason, got %v", v.Reasons)
	}
}

func TestEvaluate_MultipleFailuresAllReported(t *testing.T) {
	claims := goodClaims()
	claims["mr_enclave"] = "wrong"
	claims["mrsigner"] = "signer-mallory"
	claims["tcb_svn"] = float64(1)
	claims["debug_disabled"] = false
	v := Evaluate(testPolicy(), Evidence{PolicyID: "prod-web", Claims: claims})
	if v.Verdict != Deny {
		t.Fatalf("expected deny, got %q", v.Verdict)
	}
	if len(v.Reasons) < 4 {
		t.Fatalf("expected all 4 failures reported, got %v", v.Reasons)
	}
}

func TestEvaluate_NoChecksPolicyAllows(t *testing.T) {
	v := Evaluate(&Policy{ID: "open"}, Evidence{PolicyID: "open", Claims: map[string]any{}})
	if v.Verdict != Allow {
		t.Fatalf("expected allow for empty policy, got %q: %v", v.Verdict, v.Reasons)
	}
}
