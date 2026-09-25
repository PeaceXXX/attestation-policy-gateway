# attestation-policy-gateway

A policy-based attestation verification gateway for confidential computing. Workloads present attestation *evidence* — claims about their measurements, signer identity, TCB version, and debug mode — and the gateway evaluates that evidence against operator-defined JSON *policies*, returning an allow/deny verdict with a human-readable reason for every check. It is the admission-control point of a zero-trust deployment: no workload is trusted without fresh evidence evaluated against current policy.

> **Clean-room demo, built from public concepts only.** This project models the general shape of attestation verification (evidence → claims → policy evaluation → verdict + audit). It does not parse any vendor's quote format, performs no cryptographic signature verification, and contains no Intel-internal code, APIs, or non-public details.

## Why this exists

In a confidential-computing deployment, the relying party's core question is *"should I trust this workload with my secrets?"* Production systems answer it with an attestation service that checks evidence against explicit, versioned policy — never hardcoded values. This project implements that claim-check layer: the deterministic engine that runs after evidence is authenticated, so the design decisions behind it (deny-by-default, complete reason reporting, strict separation of policy from code) can be examined and discussed concretely.

## Architecture

```
                            POST /v1/verify
                    { policy_id, claims }  ──────────────┐
                                                         v
                    +-------------------+     +------------------+
                    |   Policy Engine   |     |      Store       |
  POST/GET/DELETE   |  (internal/policy)|     | (internal/store) |
  /v1/policies ───> |                   |     |                  |
                    |  1. required_claims│     |  policies.json   |
                    |     exact match    │     |  (atomic writes) |
                    |  2. allowed_signers│     |                  |
                    |     allow-list     │     |  audit.jsonl     |
                    |  3. min_tcb_svn    │     |  (append-only)   |
                    |     freshness      │     |                  |
                    |  4. deny_debug     │     |                  |
                    |     prod safety    │     |                  |
                    |                   │     +------------------+
                    |  deny-by-default; │               │
                    |  ALL failures     │               │ record
                    |  reported         │               v
                    +--------+----------+     +------------------+
                             │                |     Metrics      |
                             │ verdict        | (Prometheus)     |
                             │ + reasons      |                  |
                             v                | verifications_   |
                    +------------------+      | allowed_ /       |
                    |  Audit + Logs    |      | denied_total     |
                    |  (slog JSON)     |      +------------------+
                    +------------------+
```

Request flow: a verifier submits evidence → the engine loads the named policy → evaluates the four check groups in a fixed order → records the decision in the append-only audit log → increments Prometheus counters → returns the verdict. Every decision is logged with its reasons, so a denial is always explainable.

Components:

- `internal/policy` — pure policy engine: `Evaluate(policy, evidence) -> Verdict`. No I/O, no globals; deterministic output makes it trivially unit-testable.
- `internal/store` — in-memory registry with JSON file persistence. Policies in `policies.json` (atomic temp-file + rename writes); decisions in `audit.jsonl` (append-only, one JSON object per line).
- `internal/server` — REST API on stdlib `net/http` (Go 1.22+ method-aware routing), structured JSON logging via `log/slog`, graceful shutdown.
- `internal/metrics` — `gateway_verifications_total`, `gateway_allowed_total`, `gateway_denied_total` in Prometheus text format.

## Features

- **Policy CRUD** — policies are versioned JSON documents, independent of code: `required_claims` (exact-match pins on measurements/issuer), `allowed_signers` (who may have built the code), `min_tcb_svn` (platform firmware freshness), `deny_debug` (production workloads must not be debuggable).
- **Deny-by-default evaluation** — any failing check denies; unknown `policy_id` denies; all failures are reported, not just the first, so operators can fix everything in one pass.
- **Type-tolerant claim checks** — JSON numbers arriving as strings are coerced (`tcb_svn: "7"` works), with deterministic reason ordering for stable output.
- **Append-only audit trail** — every verification decision is recorded with timestamp, policy ID, verdict, and reasons; newest-first reads via `GET /v1/audit?limit=N`. Survives restarts.
- **Observability** — structured `slog` JSON logs per decision, Prometheus counters for alerting on denial spikes, `GET /healthz` liveness probe.
- **Deployable** — multi-stage Dockerfile (distroless, non-root), Kubernetes Deployment + Service manifests, resource limits.

## Quickstart

Requirements: Go 1.24+.

```bash
make build   # compile ./gateway
make test    # run unit tests
make vet     # static analysis
make run     # start on :8080, data persisted in ./data
# or directly: ./gateway --addr :8080 --data-dir data
```

Full demo flow (every output below was captured from a live server):

```bash
BASE=http://localhost:8080

# 1. Create a policy: only CI-signed builds, fresh firmware, no debug
curl -s -X POST $BASE/v1/policies \
  -H 'Content-Type: application/json' \
  -d @examples/policy-example.json
# {"id":"prod-web-v1","required_claims":{"issuer":"demo-attestation-service",
#   "mr_enclave":"aabbccddeeff...8899"},"allowed_signers":["ci-release-signer",
#   "ops-hotfix-signer"],"min_tcb_svn":5,"deny_debug":true,
#   "created_at":"2026-09-25T23:03:24Z"}        -> HTTP 201

# 2. Verify GOOD evidence -> allow
curl -s -X POST $BASE/v1/verify \
  -H 'Content-Type: application/json' \
  -d @examples/evidence-pass.json
# {"verdict":"allow","reasons":["all policy checks passed"]}

# 3. Verify BAD evidence (untrusted signer, stale TCB svn 3 < 5, debug on)
curl -s -X POST $BASE/v1/verify \
  -H 'Content-Type: application/json' \
  -d @examples/evidence-fail.json
# {"verdict":"deny","reasons":[
#   "signer \"unknown-dev-laptop-signer\" is not in allowed_signers
#     [ci-release-signer ops-hotfix-signer]",
#   "tcb_svn 3 is below minimum 5: platform firmware is out of date;
#     update and re-attest",
#   "debug mode is enabled: policy requires debug_disabled=true
#     for production workloads"]}

# 4. Unknown policy -> deny (deny-by-default)
curl -s -X POST $BASE/v1/verify \
  -H 'Content-Type: application/json' \
  -d '{"policy_id":"nope","claims":{}}'
# {"verdict":"deny","reasons":["policy \"nope\" not found"]}

# 5. Audit trail, newest first
curl -s "$BASE/v1/audit?limit=5"
# {"entries":[
#   {"timestamp":"...","policy_id":"prod-web-v1","verdict":"deny",
#    "reasons":[...]},
#   {"timestamp":"...","policy_id":"prod-web-v1","verdict":"allow",
#    "reasons":["all policy checks passed"]}]}

# 6. Metrics
curl -s $BASE/metrics
# gateway_verifications_total 2
# gateway_allowed_total 1
# gateway_denied_total 1

# 7. Policy CRUD round-trip
curl -s $BASE/v1/policies                    # {"policies":[...]}
curl -s $BASE/v1/policies/prod-web-v1        # single policy
curl -s -o /dev/null -w "%{http_code}\n" \
  -X DELETE $BASE/v1/policies/prod-web-v1    # 204
```

Restart the server and repeat steps 5–7: policies and audit history are reloaded from `./data`, so nothing is lost.

Docker and Kubernetes:

```bash
make docker-build        # builds attestation-policy-gateway:latest
kubectl apply -f k8s/    # Deployment + ClusterIP Service
```

## API reference

| Method | Path | Success | Errors |
|---|---|---|---|
| `POST` | `/v1/verify` | `200 {"verdict","reasons"}` | `400` invalid JSON / unknown fields |
| `POST` | `/v1/policies` | `201` policy document | `400` invalid policy, `409` ID already exists |
| `GET` | `/v1/policies` | `200 {"policies":[...]}` | — |
| `GET` | `/v1/policies/{id}` | `200` policy document | `404` |
| `DELETE` | `/v1/policies/{id}` | `204` | `404` |
| `GET` | `/v1/audit?limit=N` | `200 {"entries":[...]}` newest first | `400` bad limit |
| `GET` | `/metrics` | `200` Prometheus text | — |
| `GET` | `/healthz` | `200 {"status":"ok"}` | — |

Verify request body:

```json
{
  "policy_id": "prod-web-v1",
  "claims": {
    "mr_enclave": "aabbcc...",
    "mrsigner": "ci-release-signer",
    "tcb_svn": 7,
    "debug_disabled": true,
    "issuer": "demo-attestation-service"
  }
}
```

Policy document:

```json
{
  "id": "prod-web-v1",
  "required_claims": { "mr_enclave": "aabbcc...", "issuer": "demo-attestation-service" },
  "allowed_signers": ["ci-release-signer", "ops-hotfix-signer"],
  "min_tcb_svn": 5,
  "deny_debug": true
}
```

Unknown JSON fields are rejected on all write endpoints (`DisallowUnknownFields`), so typos fail loudly instead of being silently ignored.

## What this demonstrates

Interview talking points, mapped to skills:

- **Attestation** — I can explain the evidence model (measurements, signer identity, TCB SVN, debug flags) and why a verifier checks claims against *explicit policy* rather than hardcoded values: policies evolve independently of code, and different workloads need different trust levels. This project is the claim-check layer that runs after evidence authentication.
- **Policy engines** — deny-by-default evaluation, complete (not fail-fast) reason reporting, deterministic output ordering, and type coercion for claims arriving as JSON numbers or strings. The engine is a pure function of `(policy, evidence) → verdict`, which is why the test table in `internal/policy/policy_test.go` can cover allow/deny/missing-claim/debug/tcb/signer cases without any I/O.
- **Zero-trust** — "never trust, always verify": every request is evaluated fresh against current policy (no cached trust), unknown policies deny, and the append-only audit log gives a decision trail that can't be silently rewritten. The `/metrics` counters let operators alert on denial spikes.
- **Supply chain** — `allowed_signers` pins *who* may have built the code, `required_claims` pins *what* code is acceptable (exact `mr_enclave` measurement), and `min_tcb_svn` enforces platform firmware freshness: the three legs of workload supply-chain verification.
- **Production habits** — structured JSON logging with `log/slog`, graceful shutdown with timeout, atomic file writes (temp + rename, so a crash can't leave a half-written policy file), unknown-field rejection, liveness probe, and a distroless multi-stage image running as non-root.

## Limitations — how I'd productionize it

Deliberate demo simplifications, and what each would become in production:

- **No evidence authentication.** Evidence arrives as plain JSON claims. Production: verify the cryptographic envelope first (quote signature chain, revocation via CRL/OCSP-style freshness) *before* claim checks; this engine would sit behind that layer unchanged, since it only consumes verified claims.
- **Single-node JSON persistence.** Production: replicated policy store (e.g. etcd/consul) with versioning and rollback, and a tamper-evident audit log (hash-chained or WORM storage) so the decision trail itself is auditable.
- **No auth/TLS on the API.** Production: mTLS between workloads and the gateway, RBAC on policy CRUD, rate limiting on `/v1/verify`.
- **Exact-match claims only.** Production policies often need richer predicates (ranges, regex on versions, time windows). That is where a real policy language (Rego/OPA, Cedar) would replace the JSON DSL — the engine's interface (`evaluate(policy, evidence) -> verdict + reasons`) is already shaped to allow that swap.
