// SPDX-License-Identifier: Apache-2.0
package audit

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func evaluationTestArtifact(id, kind string, content any) EvaluationArtifact {
	b, _ := json.Marshal(content)
	return EvaluationArtifact{ID: id, Kind: kind, Source: "test fixture", Content: string(b), SHA256: evaluationHash(b)}
}
func evaluationFixture() EvaluationRun {
	a := evaluationTestArtifact("static-truth", "ground_truth", map[string]any{"asset": map[string]bool{"agent": true, "missing": true}, "risk": map[string]bool{"malicious": true}})
	b := evaluationTestArtifact("runtime-truth", "ground_truth", map[string]any{"runtime": map[string]bool{"attack": true, "benign": false}})
	evidence := evaluationTestArtifact("proof", "event", map[string]any{"raw_action": "block", "enforced": true, "side_effect_reached": false})
	raw := []EvaluationSample{{At: "2026-10-09T00:00:00Z", Value: 10}, {At: "2026-10-09T00:00:02Z", Value: 20}}
	samples := evaluationTestArtifact("inspect", "samples", raw)
	return EvaluationRun{Name: "fixture", Mode: "action", Status: "completed", Platform: "test", CodeVersion: "v1", ConfigHash: "config", ImageDigest: "sha256:image", ComparisonGroup: "pair", DatasetHash: "dataset", StartedAt: "2026-10-09T00:00:00Z", FinishedAt: "2026-10-09T00:00:02Z", StaticTruth: EvaluationTruth{ArtifactID: a.ID, DatasetHash: "dataset"}, RuntimeTruth: EvaluationTruth{ArtifactID: b.ID, DatasetHash: "dataset"}, Artifacts: []EvaluationArtifact{a, b, evidence, samples}, Instances: []EvaluationInstance{
		{ID: "agent", Domain: "asset", AssetType: "agent", Predicted: evaluationBool(true), Evidence: map[string][]string{"scan": {"proof"}}},
		{ID: "unexpected", Domain: "asset", Predicted: evaluationBool(true), Evidence: map[string][]string{"scan": {"proof"}}},
		{ID: "malicious", Domain: "risk", Predicted: evaluationBool(true), Evidence: map[string][]string{"scan": {"proof"}}},
		{ID: "attack", Domain: "runtime", Predicted: evaluationBool(true), Decision: "BLOCK", ResponseStatus: "executed", ActuallyBlocked: evaluationBool(true), SideEffectOccurred: evaluationBool(false), Evidence: map[string][]string{"event": {"proof"}, "detection": {"proof"}, "decision": {"proof"}, "response": {"proof"}, "side_effect": {"proof"}}},
		{ID: "benign", Domain: "runtime", Predicted: evaluationBool(false), BusinessSuccess: evaluationBool(true), Evidence: map[string][]string{"event": {"proof"}}},
	}, Series: []EvaluationSeries{{ID: "inspect", Kind: "inspect_ms", Scope: "all", Basis: "per instance", ExpectedSamples: 2, Complete: true, WindowStart: "2026-10-09T00:00:00Z", WindowEnd: "2026-10-09T00:00:02Z", ArtifactID: samples.ID, Samples: raw}}}
}
func evalMetric(t *testing.T, r EvaluationRun, key string) EvaluationMetric {
	t.Helper()
	for _, m := range r.Report.Metrics {
		if m.Key == key {
			return m
		}
	}
	t.Fatal("missing", key)
	return EvaluationMetric{}
}
func TestEvaluationIndependentTruthAndMissingEvidence(t *testing.T) {
	r := evaluationFixture()
	if err := ValidateEvaluation(&r); err != nil {
		t.Fatal(err)
	}
	c := r.Report.Counts["asset"]
	if c.TP != 1 || c.FP != 1 || c.Unknown != 1 || c.Expected != 2 {
		t.Fatalf("counts %+v", c)
	}
	if evalMetric(t, r, "asset_precision").Status != "insufficient_evidence" {
		t.Fatal("missing asset passed")
	}
	if evalMetric(t, r, "runtime_recall").Status != "passed" {
		t.Fatal("runtime detection failed")
	}
	if evalMetric(t, r, "effective_block_rate").Status != "passed" {
		t.Fatal("evidenced block not counted")
	}
	if r.Report.CapabilityStatus["runtime"] == "passed" {
		t.Fatal("missing CPU incorrectly passed")
	}
	r = evaluationFixture()
	r.Instances[3].Evidence["response"] = nil
	ValidateEvaluation(&r)
	if evalMetric(t, r, "effective_block_rate").Status != "insufficient_evidence" {
		t.Fatal("decision alone counted as effective block")
	}
	r = evaluationFixture()
	r.Instances[3].Evidence["detection"] = nil
	ValidateEvaluation(&r)
	if r.Report.Counts["runtime"].Unknown != 1 {
		t.Fatal("decision counted as detection")
	}
	r = evaluationFixture()
	r.StaticTruth.DatasetHash = "wrong-dataset"
	ValidateEvaluation(&r)
	if r.Report.Counts["asset"].TP != 0 || r.Report.Counts["asset"].Unknown != 2 {
		t.Fatal("incompatible static labels scored")
	}
	r = evaluationFixture()
	r.RuntimeTruth.ArtifactID = r.StaticTruth.ArtifactID
	if ValidateEvaluation(&r) == nil {
		t.Fatal("shared truth accepted")
	}
}
func TestEvaluationHashForgeryAndSampling(t *testing.T) {
	r := evaluationFixture()
	r.Artifacts[0].Content = `{"asset":{}}`
	if ValidateEvaluation(&r) == nil {
		t.Fatal("tampered artifact accepted")
	}
	r = evaluationFixture()
	r.Series[0].Samples[0].Value = 0
	if ValidateEvaluation(&r) == nil {
		t.Fatal("samples unbound to evidence")
	}
	r = evaluationFixture()
	r.Series[0].ExpectedSamples = 3
	if err := ValidateEvaluation(&r); err != nil {
		t.Fatal(err)
	}
	if evalMetric(t, r, "inspect_p95").Status != "incomplete_sampling" {
		t.Fatal("partial samples passed")
	}
	r = evaluationFixture()
	r.Mode = "observe"
	ValidateEvaluation(&r)
	if evalMetric(t, r, "effective_block_rate").Status == "passed" {
		t.Fatal("observe reported effective block")
	}
	m := evaluationRatio("fpr", "runtime", "FP/(FP+TN)", "< 5%", 1, 20, .05, "lt", false)
	if m.Status != "failed" {
		t.Fatal("5% fpr must fail strict threshold")
	}
	if evaluationRatio("precision", "runtime", "", "", 0, 0, .95, "gte", false).Value != nil {
		t.Fatal("zero denominator mapped to zero")
	}
}
func TestEvaluationBaselineRequiresCompleteMatchingChainSamples(t *testing.T) {
	a, b := evaluationFixture(), evaluationFixture()
	b.Mode = "baseline"
	b.ID = "baseline"
	for _, r := range []*EvaluationRun{&a, &b} {
		series := r.Series[0]
		series.Kind = "cpu_pct"
		series.Scope = "defense_chain"
		series.Basis = "host CPU %"
		r.Series = append(r.Series, series)
		r.Series[1].ID = "chain"
		if err := ValidateEvaluation(r); err != nil {
			t.Fatal(err)
		}
	}
	ApplyEvaluationBaseline(&a, b)
	if evalMetric(t, a, "cpu_increment").Status != "passed" {
		t.Fatal("matching baseline missing")
	}
	a = evaluationFixture()
	a.Series = b.Series
	ValidateEvaluation(&a)
	b.ConfigHash = "different"
	ApplyEvaluationBaseline(&a, b)
	if evalMetric(t, a, "cpu_increment").Value != nil {
		t.Fatal("mismatched metadata compared")
	}
	b.ConfigHash = a.ConfigHash
	b.Status = "cancelled"
	ApplyEvaluationBaseline(&a, b)
	if evalMetric(t, a, "cpu_increment").Value != nil {
		t.Fatal("cancelled baseline compared")
	}
	if evaluationSeriesComplete(EvaluationSeries{Complete: true, Kind: "cpu_pct", ExpectedSamples: 2, WindowStart: "2026-10-09T00:00:00Z", WindowEnd: "2026-10-09T01:00:00Z", Samples: []EvaluationSample{{At: "2026-10-09T00:00:00Z"}, {At: "2026-10-09T00:00:02Z"}}}, false) {
		t.Fatal("uncovered CPU window passed")
	}
}
func TestEvaluationStoreRestartHistoryCancel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Init(); err != nil {
		t.Fatal(err)
	}
	r := evaluationFixture()
	first, err := s.CreateEvaluation(r)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.CreateEvaluation(r)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == second.ID {
		t.Fatal("history overwritten")
	}
	s.Close()
	s, err = NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.Init(); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetEvaluation(first.ID)
	if err != nil || got.Report.Counts["runtime"].TP != 1 {
		t.Fatalf("restart %v %+v", err, got)
	}
	rows, total, err := s.ListEvaluationInstances(first.ID, "asset", "unknown", "", "", 20, 0)
	if err != nil || total != 1 || len(rows) != 1 || rows[0].ID != "missing" {
		t.Fatalf("filtered evidence %v %+v", err, rows)
	}
	if _, err = s.CancelEvaluation(first.ID); err != ErrEvaluationFinished {
		t.Fatal("completed cancelled", err)
	}
	r.Status = "running"
	running, err := s.CreateEvaluation(r)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, err := s.CancelEvaluation(running.ID)
	if err != nil || cancelled.Status != "cancelled" || cancelled.Report.CapabilityStatus["runtime"] == "passed" {
		t.Fatalf("cancel %v %+v", err, cancelled)
	}
	if _, err = s.GetEvaluationArtifact(running.ID, "proof"); err != nil {
		t.Fatal("cancel removed proof", err)
	}
	if _, err = s.GetEvaluationArtifact(second.ID, "missing"); err != ErrEvaluationNotFound {
		t.Fatal("missing artifact", err)
	}
}

func TestEvaluationTruthCannotMasqueradeAsResponseEvidence(t *testing.T) {
	r := evaluationFixture()
	r.Instances[3].Evidence["response"] = []string{"runtime-truth"}
	if ValidateEvaluation(&r) == nil {
		t.Fatal("ground truth used as execution receipt")
	}
	r = evaluationFixture()
	r.Instances = append(r.Instances, EvaluationInstance{ID: "unlabeled", Domain: "runtime", Expected: evaluationBool(false), Predicted: evaluationBool(false), Evidence: map[string][]string{"event": {"proof"}}})
	if err := ValidateEvaluation(&r); err != nil {
		t.Fatal(err)
	}
	c := r.Report.Counts["runtime"]
	if c.TN != 1 || c.Unknown != 1 || c.ExpectedUnknown != 1 {
		t.Fatal("unlabeled instance became TN", c)
	}
	r = evaluationFixture()
	r.Series = append(r.Series, r.Series[0])
	r.Series[1].ID = "another"
	if ValidateEvaluation(&r) == nil {
		t.Fatal("ambiguous duplicate sample scope accepted")
	}
	if evaluationKnownMetadata("unknown") {
		t.Fatal("unknown metadata considered comparable")
	}
}

func TestEvaluationStaticCapabilityRequiresSixLabeledAssetClasses(t *testing.T) {
	r := evaluationFixture()
	labels := map[string]bool{}
	instances := []EvaluationInstance{}
	for _, kind := range []string{"agent", "model", "mcp", "skill", "plugin", "tool"} {
		id := kind + ".test"
		labels[id] = true
		assetType := kind
		if kind == "mcp" {
			assetType = "mcp_server"
		}
		instances = append(instances, EvaluationInstance{ID: id, Domain: "asset", AssetType: assetType, Predicted: evaluationBool(true), Evidence: map[string][]string{"scan": {"proof"}}})
	}
	for _, i := range r.Instances {
		if i.Domain != "asset" {
			instances = append(instances, i)
		}
	}
	r.Instances = instances
	r.Artifacts[0] = evaluationTestArtifact("static-truth", "ground_truth", map[string]any{"asset": labels, "risk": map[string]bool{"malicious": true}})
	if err := ValidateEvaluation(&r); err != nil {
		t.Fatal(err)
	}
	if r.Report.CapabilityStatus["static"] != "passed" {
		t.Fatal("complete static evaluation did not pass", r.Report.CapabilityStatus)
	}
	r.CodeVersion = "unknown"
	if err := ValidateEvaluation(&r); err != nil {
		t.Fatal(err)
	}
	if r.Report.CapabilityStatus["static"] == "passed" {
		t.Fatal("missing provenance passed")
	}
	r.CodeVersion = "v1"
	r.Instances = r.Instances[1:]
	if err := ValidateEvaluation(&r); err != nil {
		t.Fatal(err)
	}
	if r.Report.CapabilityStatus["static"] == "passed" {
		t.Fatal("missing class passed")
	}
}
