// Chain-context injection probes (T011B2). The trusted ChainContext is a Go
// argument only: the closed write envelope must refuse ANY chain-context
// bytes in the submitted document — a top-level "chainContext" member, an id,
// an interface inventory, or a node field inside the quarantine bucket that
// would satisfy a reference. These cases are RED before the closed envelope
// and the never-promoted bucket exist, and prove that context cannot be
// smuggled through the JSON path (handoff §"no context/client IDs in submitted
// JSON", D-047 trust boundary).

package contract_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/suchimauz/raylane/internal/domain"
	"github.com/suchimauz/raylane/internal/domain/nodes"
)

// chainDocWith returns a canonical vless envelope with an ACTIVE predecessor
// reference, with the fields object extended by the given raw member text.
func chainDocWith(extraFields string) []byte {
	active := `{"server":"v.example","serverPort":443,"transport":"ws","security":"tls","chainMode":"predecessor","chainNodeId":"peer-v"}`
	fields := `"active":` + active + `,"inactive":{},"unknown":{}`
	if extraFields != "" {
		fields += "," + extraFields
	}
	return []byte(`{"protocol":"vless","fields":{` + fields + `}}`)
}

// TestChainContextNotInjectableViaDocument: every attempt to supply the trusted
// context (or to launder a reference through the quarantine bucket) inside the
// submitted JSON is refused, and no verdict ever echoes the injected bytes.
func TestChainContextNotInjectableViaDocument(t *testing.T) {
	p := loadProfile(t)
	presence := map[string]bool{"uuid": true}

	// CONTROL: the same node with the context supplied as the Go argument is
	// valid + applicable — the refusal below is about the channel, not the mode.
	original := chainDocWith("")
	gotOK, err := nodes.ValidateDocumentWithContext(p, original, presence,
		refContext("self-vless", [][2]string{{"peer-v", "vless"}}))
	if err != nil {
		t.Fatalf("control envelope must decode: %v", err)
	}
	if gotOK.Validation != domain.ValidationValid || !gotOK.Result.Applicable {
		t.Fatalf("control broken: want Valid+Applicable, got %+v", gotOK.Result)
	}

	// A reference resolved from a TRUSTED context is valid; the same
	// "self-vless" id must never be accepted because a document claims it.
	injections := map[string]string{
		// Root-level members (outside the closed fields object).
		"top-level-chain-context": `{"chainContext":"injected",`,
		"top-level-node-id":       `{"id":"injected",`,
		"top-level-ifaces":        `{"interfaces":["injected"],`,
		// Extra members inside the closed fields object.
		"fields-extra-inventory":   `"inventory":{"injected":1}`,
		"fields-extra-chain-field": `"chainPeer":"injected"`,
		// Extra entry inside one of the three buckets.
		"bucket-extra-entry": `"unknown":{"chainContext":"injected"}`,
	}
	for name, extra := range injections {
		var doc []byte
		switch name {
		case "top-level-chain-context", "top-level-node-id", "top-level-ifaces":
			// Inject a root-level member before the closed "fields" object.
			doc = []byte(extra + string(chainDocWith("")[1:]))
		default:
			doc = chainDocWith(extra)
		}
		res, err := nodes.ValidateDocumentWithContext(p, doc, presence,
			refContext("self-vless", [][2]string{{"peer-v", "vless"}}))
		if !errors.Is(err, nodes.ErrNotANodeEnvelope) {
			t.Errorf("%s: injected context must be refused as non-envelope, got err=%v", name, err)
			continue
		}
		if res.Result.Status == nodes.Valid {
			t.Errorf("%s: injected context must never validate", name)
		}
		assertChainCanary(t, name, res.Result)
	}
}

// TestChainQuarantinedCompanionNeverSatisfiesReference: an ACTIVE predecessor
// mode whose companion sits ONLY in the quarantine bucket stays invalid: the
// bucket never satisfies R1 and never reaches the reference resolver.
func TestChainQuarantinedCompanionNeverSatisfiesReference(t *testing.T) {
	p := loadProfile(t)
	active := `{"server":"v.example","serverPort":443,"transport":"ws","security":"tls","chainMode":"predecessor"}`
	doc := []byte(`{"protocol":"vless","fields":{"active":` + active +
		`,"inactive":{},"unknown":{"chainNodeId":"` + chainNodeCanary + `"}}}`)
	res, err := nodes.ValidateDocumentWithContext(p, doc, map[string]bool{"uuid": true},
		refContext("self-vless", [][2]string{{chainNodeCanary, "vless"}}))
	if err != nil {
		t.Fatalf("canonical envelope must decode: %v", err)
	}
	if res.Result.Status == nodes.Valid || res.Result.Applicable {
		t.Fatalf("quarantined companion must not satisfy a reference: %+v", res.Result)
	}
	if !hasIssue(res.Result, nodes.IssueDependencyMissing, "chainNodeId") {
		t.Fatalf("want dependencyMissing on chainNodeId, got %+v", res.Result.Issues)
	}
	if !hasIssue(res.Result, nodes.IssueQuarantineBucketNotEmpty, "unknown") {
		t.Fatalf("want the generic quarantine issue, got %+v", res.Result.Issues)
	}
	assertChainCanary(t, "quarantined companion", res.Result)
	// The exact submitted bytes stay preserved for honest draft storage.
	if !bytes.Equal(res.Document.Raw, doc) {
		t.Fatalf("exact raw must be preserved for an invalid chain draft (FR-009)")
	}
}
