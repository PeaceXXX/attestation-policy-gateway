// Package metrics exposes verification counters in Prometheus text format.
package metrics

import (
	"fmt"
	"strings"
	"sync/atomic"
)

// Counters holds the gateway's verification counters.
type Counters struct {
	verifications atomic.Int64
	allowed       atomic.Int64
	denied        atomic.Int64
}

// Observe records one verification decision.
func (c *Counters) Observe(verdict string) {
	c.verifications.Add(1)
	switch verdict {
	case "allow":
		c.allowed.Add(1)
	case "deny":
		c.denied.Add(1)
	}
}

// Snapshot returns the current counter values.
func (c *Counters) Snapshot() (verifications, allowed, denied int64) {
	return c.verifications.Load(), c.allowed.Load(), c.denied.Load()
}

// Render returns the counters in Prometheus exposition format.
func (c *Counters) Render() string {
	v, a, d := c.Snapshot()
	var b strings.Builder
	b.WriteString("# HELP gateway_verifications_total Total attestation verifications performed.\n")
	b.WriteString("# TYPE gateway_verifications_total counter\n")
	fmt.Fprintf(&b, "gateway_verifications_total %d\n", v)
	b.WriteString("# HELP gateway_allowed_total Total verifications with an allow verdict.\n")
	b.WriteString("# TYPE gateway_allowed_total counter\n")
	fmt.Fprintf(&b, "gateway_allowed_total %d\n", a)
	b.WriteString("# HELP gateway_denied_total Total verifications with a deny verdict.\n")
	b.WriteString("# TYPE gateway_denied_total counter\n")
	fmt.Fprintf(&b, "gateway_denied_total %d\n", d)
	return b.String()
}
