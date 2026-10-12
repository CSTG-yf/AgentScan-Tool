// SPDX-License-Identifier: Apache-2.0
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// Evaluation inputs are post-run evidence. They never enter production detectors.
type EvaluationArtifact struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Source  string `json:"source"`
	SHA256  string `json:"sha256"`
	Content string `json:"content"`
}
type EvaluationTruth struct {
	ArtifactID  string `json:"artifact_id"`
	SHA256      string `json:"sha256"`
	DatasetHash string `json:"dataset_hash"`
}
type EvaluationInstance struct {
	ID                 string              `json:"id"`
	Domain             string              `json:"domain"` // asset, risk, runtime
	AssetType          string              `json:"asset_type,omitempty"`
	RiskKind           string              `json:"risk_kind,omitempty"`
	Scenario           string              `json:"scenario,omitempty"`
	Connector          string              `json:"connector,omitempty"`
	Expected           *bool               `json:"expected"` // populated only from independent ground truth
	Predicted          *bool               `json:"predicted"`
	BusinessSuccess    *bool               `json:"business_success"`
	Decision           string              `json:"decision,omitempty"`
	ResponseStatus     string              `json:"response_status,omitempty"`
	ActuallyBlocked    *bool               `json:"actually_blocked"`
	SideEffectOccurred *bool               `json:"side_effect_occurred"`
	Evidence           map[string][]string `json:"evidence"`
	Outcome            string              `json:"outcome"`
}
type EvaluationSample struct {
	At    string  `json:"at"`
	Value float64 `json:"value"`
}
type EvaluationSeries struct {
	ID              string             `json:"id"`
	Kind            string             `json:"kind"`  // inspect_ms, e2e_ms, cpu_pct
	Scope           string             `json:"scope"` // gateway, container:<name>, defense_chain
	Basis           string             `json:"basis"`
	WindowStart     string             `json:"window_start"`
	WindowEnd       string             `json:"window_end"`
	ExpectedSamples int                `json:"expected_samples"`
	Complete        bool               `json:"complete"`
	ArtifactID      string             `json:"artifact_id"`
	Samples         []EvaluationSample `json:"samples"`
}
type EvaluationRun struct {
	ID                string               `json:"id"`
	Name              string               `json:"name"`
	Mode              string               `json:"mode"`
	Platform          string               `json:"platform"`
	CodeVersion       string               `json:"code_version"`
	ConfigHash        string               `json:"config_hash"`
	ImageDigest       string               `json:"image_digest"`
	DatasetHash       string               `json:"dataset_hash"`
	StaticDatasetHash string               `json:"static_dataset_hash"`
	ComparisonGroup   string               `json:"comparison_group"`
	StaticTruth       EvaluationTruth      `json:"static_truth"`
	RuntimeTruth      EvaluationTruth      `json:"runtime_truth"`
	StartedAt         string               `json:"started_at"`
	FinishedAt        string               `json:"finished_at"`
	CreatedAt         string               `json:"created_at"`
	Status            string               `json:"status"`
	EvidenceDirectory string               `json:"evidence_directory"`
	Notes             []string             `json:"notes"`
	Instances         []EvaluationInstance `json:"instances,omitempty"`
	Artifacts         []EvaluationArtifact `json:"artifacts,omitempty"`
	Series            []EvaluationSeries   `json:"series,omitempty"`
	Report            EvaluationReport     `json:"report"`
}
type EvaluationCounts struct {
	ExpectedUnknown   int `json:"expected_unknown"`
	DiscoveredUnknown int `json:"discovered_unknown"`
	TP                int `json:"tp"`
	FP                int `json:"fp"`
	TN                int `json:"tn"`
	FN                int `json:"fn"`
	Unknown           int `json:"unknown"`
	Expected          int `json:"expected"`
	Discovered        int `json:"discovered"`
	Total             int `json:"total"`
}
type EvaluationMetric struct {
	Key         string   `json:"key"`
	Domain      string   `json:"domain"`
	Value       *float64 `json:"value"`
	Numerator   *int     `json:"numerator"`
	Denominator *int     `json:"denominator"`
	Unit        string   `json:"unit"`
	Formula     string   `json:"formula"`
	Target      string   `json:"target"`
	Status      string   `json:"status"` // passed, failed, not_evaluated, insufficient_evidence, incomplete_sampling
	Reason      string   `json:"reason"`
}
type EvaluationDistribution struct {
	ID              string   `json:"id"`
	Kind            string   `json:"kind"`
	Scope           string   `json:"scope"`
	Basis           string   `json:"basis"`
	Samples         int      `json:"samples"`
	ExpectedSamples int      `json:"expected_samples"`
	WindowStart     string   `json:"window_start"`
	WindowEnd       string   `json:"window_end"`
	P50             *float64 `json:"p50"`
	P95             *float64 `json:"p95"`
	P99             *float64 `json:"p99"`
	Status          string   `json:"status"`
	ArtifactID      string   `json:"artifact_id"`
}
type EvaluationBreakdown struct {
	Dimension string             `json:"dimension"`
	Name      string             `json:"name"`
	Domain    string             `json:"domain"`
	Counts    EvaluationCounts   `json:"counts"`
	Metrics   []EvaluationMetric `json:"metrics"`
}
type EvaluationReport struct {
	ProvenanceComplete bool                        `json:"provenance_complete"`
	Counts             map[string]EvaluationCounts `json:"counts"`
	Metrics            []EvaluationMetric          `json:"metrics"`
	CapabilityStatus   map[string]string           `json:"capability_status"`
	Breakdowns         []EvaluationBreakdown       `json:"breakdowns"`
	Distributions      []EvaluationDistribution    `json:"distributions"`
	Decisions          map[string]int              `json:"decisions"`
	Responses          map[string]int              `json:"responses"`
	Business           map[string]int              `json:"business"`
	RiskHits           map[string]int              `json:"risk_hits"`
}

func evaluationHash(content []byte) string {
	h := sha256.Sum256(content)
	return hex.EncodeToString(h[:])
}
func evaluationBool(v bool) *bool { return &v }
func hasEvaluationEvidence(i EvaluationInstance, stage string) bool {
	return len(i.Evidence[stage]) > 0
}

// ValidateEvaluation binds labels and raw sampling to stored artifacts before scoring.
// Missing records remain unknown, never true negatives or zero latency.
func ValidateEvaluation(run *EvaluationRun) error {
	if !map[string]bool{"baseline": true, "observe": true, "action": true}[run.Mode] {
		return fmt.Errorf("mode must be baseline, observe or action")
	}
	if !map[string]bool{"completed": true, "running": true, "failed": true, "cancelled": true}[run.Status] {
		return fmt.Errorf("unsupported evaluation status")
	}
	for _, value := range []string{run.StartedAt, run.FinishedAt} {
		if value != "" {
			if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
				return fmt.Errorf("invalid execution time")
			}
		}
	}
	if strings.TrimSpace(run.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if len(run.Instances) > 50000 || len(run.Artifacts) > 100000 || len(run.Series) > 500 {
		return fmt.Errorf("evaluation exceeds record limits")
	}
	artifacts := map[string]EvaluationArtifact{}
	for _, a := range run.Artifacts {
		if a.ID == "" || strings.TrimSpace(a.Source) == "" || !json.Valid([]byte(a.Content)) || artifacts[a.ID].ID != "" {
			return fmt.Errorf("invalid or duplicate artifact %q", a.ID)
		}
		if a.SHA256 != evaluationHash([]byte(a.Content)) {
			return fmt.Errorf("artifact %s SHA-256 mismatch", a.ID)
		}
		artifacts[a.ID] = a
	}
	for _, t := range []*EvaluationTruth{&run.StaticTruth, &run.RuntimeTruth} {
		t.SHA256 = artifacts[t.ArtifactID].SHA256
	}
	truths := map[string]map[string]bool{}
	for _, item := range []struct {
		truth   EvaluationTruth
		domains []string
	}{{run.StaticTruth, []string{"asset", "risk"}}, {run.RuntimeTruth, []string{"runtime"}}} {
		if item.truth.ArtifactID == "" {
			continue
		}
		a, ok := artifacts[item.truth.ArtifactID]
		if !ok || a.Kind != "ground_truth" {
			return fmt.Errorf("ground truth artifact not found")
		}
		var labels map[string]map[string]bool
		if err := json.Unmarshal([]byte(a.Content), &labels); err != nil {
			return fmt.Errorf("invalid ground truth labels")
		}
		datasetHash := run.DatasetHash
		if item.domains[0] == "asset" && run.StaticDatasetHash != "" {
			datasetHash = run.StaticDatasetHash
		}
		if item.truth.DatasetHash == "" || item.truth.DatasetHash != datasetHash {
			continue
		} // retained but incompatible labels are not scored
		for _, domain := range item.domains {
			truths[domain] = labels[domain]
		}
	}
	if run.StaticTruth.ArtifactID != "" && run.StaticTruth.ArtifactID == run.RuntimeTruth.ArtifactID {
		return fmt.Errorf("static and runtime ground truths must be independent")
	}
	seen := map[string]bool{}
	for n := range run.Instances {
		i := &run.Instances[n]
		if !map[string]bool{"asset": true, "risk": true, "runtime": true}[i.Domain] || i.ID == "" || seen[i.Domain+":"+i.ID] {
			return fmt.Errorf("invalid or duplicate instance %s", i.ID)
		}
		seen[i.Domain+":"+i.ID] = true
		i.AssetType = strings.ToLower(strings.TrimSpace(i.AssetType))
		switch i.AssetType {
		case "mcp_server":
			i.AssetType = "mcp"
		case "skills":
			i.AssetType = "skill"
		case "plugins":
			i.AssetType = "plugin"
		case "tools":
			i.AssetType = "tool"
		}
		i.Expected = nil
		if labels := truths[i.Domain]; labels != nil {
			if value, ok := labels[i.ID]; ok {
				i.Expected = evaluationBool(value)
			} else if i.Domain != "runtime" {
				i.Expected = evaluationBool(false)
			}
		}
		for stage, refs := range i.Evidence {
			if !map[string]bool{"scan": true, "event": true, "detection": true, "decision": true, "response": true, "side_effect": true, "attack_chain": true}[stage] {
				return fmt.Errorf("invalid evidence stage %s", stage)
			}
			for _, ref := range refs {
				if artifacts[ref].Kind == "ground_truth" || artifacts[ref].Kind == "samples" {
					return fmt.Errorf("truth or samples cannot serve as %s evidence", stage)
				}
				if artifacts[ref].ID == "" {
					return fmt.Errorf("unknown artifact %s", ref)
				}
			}
		}
		if !map[string]bool{"": true, "executed": true, "failed": true, "would_block": true, "not_requested": true}[i.ResponseStatus] {
			return fmt.Errorf("invalid response status")
		}
		if i.Predicted != nil && !(hasEvaluationEvidence(*i, "scan") || hasEvaluationEvidence(*i, "detection") || (i.Domain == "runtime" && hasEvaluationEvidence(*i, "event"))) {
			i.Predicted = nil
		}
		if i.Domain == "runtime" && i.Predicted != nil && *i.Predicted && !hasEvaluationEvidence(*i, "detection") {
			i.Predicted = nil
		}
		i.Outcome = "unknown"
		if i.Expected != nil && i.Predicted != nil {
			if *i.Expected {
				if *i.Predicted {
					i.Outcome = "tp"
				} else {
					i.Outcome = "fn"
				}
			} else {
				if *i.Predicted {
					i.Outcome = "fp"
				} else {
					i.Outcome = "tn"
				}
			}
		}
	}
	for domain, labels := range truths {
		for id, label := range labels {
			if !seen[domain+":"+id] {
				run.Instances = append(run.Instances, EvaluationInstance{ID: id, Domain: domain, Expected: evaluationBool(label), Outcome: "unknown", Evidence: map[string][]string{}})
			}
		}
	}
	sort.Slice(run.Instances, func(i, j int) bool {
		a, b := run.Instances[i], run.Instances[j]
		if a.Domain != b.Domain {
			return a.Domain < b.Domain
		}
		return a.ID < b.ID
	})
	seriesIDs := map[string]bool{}
	seriesScopes := map[string]bool{}
	for _, series := range run.Series {
		if series.ID == "" || seriesIDs[series.ID] || !map[string]bool{"inspect_ms": true, "e2e_ms": true, "cpu_pct": true}[series.Kind] {
			return fmt.Errorf("invalid sample series")
		}
		seriesIDs[series.ID] = true
		key := series.Kind + ":" + series.Scope
		if seriesScopes[key] {
			return fmt.Errorf("duplicate sample scope %s", key)
		}
		seriesScopes[key] = true
		if series.ExpectedSamples < 0 || len(series.Samples) > 100000 {
			return fmt.Errorf("invalid sample count")
		}
		start, e1 := time.Parse(time.RFC3339Nano, series.WindowStart)
		end, e2 := time.Parse(time.RFC3339Nano, series.WindowEnd)
		if e1 != nil || e2 != nil || end.Before(start) || series.Basis == "" || series.Scope == "" {
			return fmt.Errorf("sample series needs basis, scope and valid window")
		}
		a, ok := artifacts[series.ArtifactID]
		if !ok {
			return fmt.Errorf("sample evidence missing")
		}
		var raw []EvaluationSample
		if json.Unmarshal([]byte(a.Content), &raw) != nil {
			return fmt.Errorf("sample evidence must contain raw samples")
		}
		b1, _ := json.Marshal(raw)
		b2, _ := json.Marshal(series.Samples)
		if string(b1) != string(b2) {
			return fmt.Errorf("sample series differs from evidence")
		}
		for _, sample := range series.Samples {
			at, err := time.Parse(time.RFC3339Nano, sample.At)
			if err != nil || at.Before(start) || at.After(end) || sample.Value < 0 || math.IsNaN(sample.Value) || math.IsInf(sample.Value, 0) {
				return fmt.Errorf("invalid sample value or time")
			}
		}
	}
	run.Report = ScoreEvaluation(*run)
	return nil
}

func evaluationCounts(instances []EvaluationInstance, domain string) EvaluationCounts {
	c := EvaluationCounts{}
	for _, i := range instances {
		if i.Domain != domain {
			continue
		}
		c.Total++
		if i.Expected == nil {
			c.ExpectedUnknown++
		}
		if i.Predicted == nil {
			c.DiscoveredUnknown++
		}
		if i.Expected != nil && *i.Expected {
			c.Expected++
		}
		if i.Predicted != nil && *i.Predicted {
			c.Discovered++
		}
		switch i.Outcome {
		case "tp":
			c.TP++
		case "fp":
			c.FP++
		case "tn":
			c.TN++
		case "fn":
			c.FN++
		default:
			c.Unknown++
		}
	}
	return c
}
func evaluationRatio(key, domain, formula, target string, n, d int, threshold float64, comparison string, incomplete bool) EvaluationMetric {
	m := EvaluationMetric{Key: key, Domain: domain, Formula: formula, Target: target, Unit: "ratio", Numerator: &n, Denominator: &d, Status: "not_evaluated", Reason: "无可用分母"}
	if d == 0 {
		return m
	}
	v := float64(n) / float64(d)
	m.Value = &v
	m.Reason = ""
	if incomplete {
		m.Status = "insufficient_evidence"
		m.Reason = "存在未知实例或批次未完成"
		return m
	}
	m.Status = "passed"
	if (comparison == "gte" && v < threshold) || (comparison == "lt" && v >= threshold) {
		m.Status = "failed"
	}
	return m
}
func evaluationRates(domain string, c EvaluationCounts, incomplete bool) []EvaluationMetric {
	return []EvaluationMetric{
		evaluationRatio(domain+"_precision", domain, "TP / (TP + FP)", map[string]string{"asset": "≥ 99%", "risk": "≥ 95%", "runtime": "参考指标"}[domain], c.TP, c.TP+c.FP, map[string]float64{"asset": .99, "risk": .95, "runtime": 0}[domain], "gte", incomplete),
		evaluationRatio(domain+"_recall", domain, "TP / (TP + FN)", "≥ 95%", c.TP, c.TP+c.FN, .95, "gte", incomplete),
		evaluationRatio(domain+"_fnr", domain, "FN / (TP + FN)", "< 5%", c.FN, c.TP+c.FN, .05, "lt", incomplete),
		evaluationRatio(domain+"_fpr", domain, "FP / (FP + TN)", "< 5%", c.FP, c.FP+c.TN, .05, "lt", incomplete),
	}
}
func evaluationPercentile(values []float64, q float64) *float64 {
	if len(values) == 0 {
		return nil
	}
	sort.Float64s(values)
	v := values[int(math.Ceil(q*float64(len(values))))-1]
	return &v
}
func evaluationSeriesComplete(series EvaluationSeries, incomplete bool) bool {
	if incomplete || !series.Complete || series.ExpectedSamples <= 0 || len(series.Samples) != series.ExpectedSamples {
		return false
	}
	if series.Kind != "cpu_pct" {
		return true
	}
	if len(series.Samples) < 2 {
		return false
	}
	times := []time.Time{}
	for _, sample := range series.Samples {
		t, err := time.Parse(time.RFC3339Nano, sample.At)
		if err != nil {
			return false
		}
		times = append(times, t)
	}
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
	gaps := []float64{}
	for n := 1; n < len(times); n++ {
		gap := times[n].Sub(times[n-1]).Seconds()
		if gap <= 0 {
			return false
		}
		gaps = append(gaps, gap)
	}
	interval := *evaluationPercentile(gaps, .5)
	edgeLimit := math.Max(5, 3*interval)
	gapLimit := math.Max(10, 5*interval)
	start, _ := time.Parse(time.RFC3339Nano, series.WindowStart)
	end, _ := time.Parse(time.RFC3339Nano, series.WindowEnd)
	if times[0].Sub(start).Seconds() > edgeLimit || end.Sub(times[len(times)-1]).Seconds() > edgeLimit {
		return false
	}
	for _, gap := range gaps {
		if gap > gapLimit {
			return false
		}
	}
	return true
}

func ScoreEvaluation(run EvaluationRun) EvaluationReport { return scoreEvaluation(run, true) }
func scoreEvaluation(run EvaluationRun, includeBreakdowns bool) EvaluationReport {
	r := EvaluationReport{Counts: map[string]EvaluationCounts{}, Metrics: []EvaluationMetric{}, CapabilityStatus: map[string]string{}, Breakdowns: []EvaluationBreakdown{}, Distributions: []EvaluationDistribution{}, Decisions: map[string]int{}, Responses: map[string]int{}, Business: map[string]int{"success": 0, "failed": 0, "unknown": 0, "total": 0}, RiskHits: map[string]int{}}
	r.ProvenanceComplete = run.StartedAt != "" && run.FinishedAt != ""
	for _, v := range []string{run.Platform, run.CodeVersion, run.ConfigHash, run.ImageDigest, run.DatasetHash} {
		if !evaluationKnownMetadata(v) {
			r.ProvenanceComplete = false
		}
	}
	incomplete := run.Status != "completed"
	for _, domain := range []string{"asset", "risk", "runtime"} {
		c := evaluationCounts(run.Instances, domain)
		r.Counts[domain] = c
		for _, m := range evaluationRates(domain, c, incomplete || c.Unknown > 0) {
			if domain == "asset" && (strings.HasSuffix(m.Key, "recall") || strings.HasSuffix(m.Key, "fpr")) {
				continue
			}
			r.Metrics = append(r.Metrics, m)
		}
	}
	blocked, shouldBlock, blockUnknown := 0, 0, 0
	for _, i := range run.Instances {
		if i.Domain == "risk" && i.Predicted != nil {
			if _, ok := r.RiskHits[i.RiskKind]; !ok {
				r.RiskHits[i.RiskKind] = 0
			}
			if *i.Predicted {
				r.RiskHits[i.RiskKind]++
			}
		}
		if i.Domain != "runtime" {
			continue
		}
		r.Decisions[strings.ToUpper(i.Decision)]++
		r.Responses[i.ResponseStatus]++
		if i.Expected == nil {
			continue
		}
		if !*i.Expected {
			r.Business["total"]++
			if i.BusinessSuccess == nil || !hasEvaluationEvidence(i, "event") {
				r.Business["unknown"]++
			} else if *i.BusinessSuccess {
				r.Business["success"]++
			} else {
				r.Business["failed"]++
			}
			continue
		}
		shouldBlock++
		if i.ActuallyBlocked == nil || i.SideEffectOccurred == nil || !hasEvaluationEvidence(i, "side_effect") || (*i.ActuallyBlocked && !hasEvaluationEvidence(i, "response")) {
			blockUnknown++
			continue
		}
		if run.Mode == "action" && *i.ActuallyBlocked && !*i.SideEffectOccurred && i.ResponseStatus == "executed" {
			blocked++
		}
	}
	r.Metrics = append(r.Metrics, evaluationRatio("effective_block_rate", "runtime", "实际阻断且副作用未发生 / 应阻断实例", "≥ 95%", blocked, shouldBlock, .95, "gte", incomplete || blockUnknown > 0 || run.Mode != "action"), evaluationRatio("business_success_rate", "runtime", "正常业务成功数 / 正常请求总数", "100%", r.Business["success"], r.Business["total"], 1, "gte", incomplete || r.Business["unknown"] > 0 || r.Counts["runtime"].Unknown > 0))
	if includeBreakdowns {
		for _, domain := range []string{"asset", "risk", "runtime"} {
			for _, dim := range []string{"asset_type", "scenario", "connector"} {
				if domain != "runtime" && dim != "asset_type" {
					continue
				}
				if domain == "runtime" && dim == "asset_type" {
					continue
				}
				groups := map[string][]EvaluationInstance{}
				for _, i := range run.Instances {
					if i.Domain != domain {
						continue
					}
					name := map[string]string{"asset_type": i.AssetType, "scenario": i.Scenario, "connector": i.Connector}[dim]
					if name == "" {
						name = "unknown"
					}
					groups[name] = append(groups[name], i)
				}
				keys := []string{}
				for k := range groups {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, name := range keys {
					c := evaluationCounts(groups[name], domain)
					metrics := evaluationRates(domain, c, incomplete || c.Unknown > 0)
					if domain == "runtime" {
						subset := run
						subset.Instances = groups[name]
						subset.Series = nil
						subsetReport := scoreEvaluation(subset, false)
						for _, m := range subsetReport.Metrics {
							if m.Key == "effective_block_rate" || m.Key == "business_success_rate" {
								metrics = append(metrics, m)
							}
						}
					}
					r.Breakdowns = append(r.Breakdowns, EvaluationBreakdown{Dimension: dim, Name: name, Domain: domain, Counts: c, Metrics: metrics})
				}
			}
		}
	}
	inspectFound := false
	for _, series := range run.Series {
		values := []float64{}
		for _, s := range series.Samples {
			values = append(values, s.Value)
		}
		d := EvaluationDistribution{ID: series.ID, Kind: series.Kind, Scope: series.Scope, Basis: series.Basis, Samples: len(values), ExpectedSamples: series.ExpectedSamples, WindowStart: series.WindowStart, WindowEnd: series.WindowEnd, P50: evaluationPercentile(values, .50), P95: evaluationPercentile(values, .95), P99: evaluationPercentile(values, .99), Status: "complete", ArtifactID: series.ArtifactID}
		if !evaluationSeriesComplete(series, incomplete) {
			d.Status = "incomplete_sampling"
		}
		r.Distributions = append(r.Distributions, d)
		if series.Kind == "inspect_ms" && series.Scope == "all" {
			inspectFound = true
			m := EvaluationMetric{Key: "inspect_p95", Domain: "runtime", Value: d.P95, Unit: "ms", Formula: "Inspect 时延原始样本的 nearest-rank P95", Target: "< 1,000 ms", Status: "passed"}
			if d.Status != "complete" {
				m.Status = "incomplete_sampling"
				m.Reason = "样本数或采样窗口不完整"
			} else if d.P95 == nil {
				m.Status = "not_evaluated"
			} else if *d.P95 >= 1000 {
				m.Status = "failed"
			}
			r.Metrics = append(r.Metrics, m)
		}
	}
	if !inspectFound {
		r.Metrics = append(r.Metrics, EvaluationMetric{Key: "inspect_p95", Domain: "runtime", Unit: "ms", Target: "< 1,000 ms", Status: "not_evaluated", Reason: "缺少 Inspect 原始样本"})
	}
	r.Metrics = append(r.Metrics, EvaluationMetric{Key: "cpu_increment", Domain: "runtime", Unit: "percentage_points", Formula: "整体防御链路 Action P95 - Baseline P95（同口径、同基线）", Target: "≤ 5 个百分点", Status: "not_evaluated", Reason: "需要相同基线的完整 Action / Baseline CPU 样本"})
	setEvaluationCapabilityStatus(&r)
	return r
}
func setEvaluationCapabilityStatus(r *EvaluationReport) {
	required := map[string][]string{"static": {"asset_precision", "asset_fnr", "risk_precision", "risk_recall", "risk_fnr"}, "runtime": {"runtime_recall", "runtime_fpr", "effective_block_rate", "business_success_rate", "inspect_p95", "cpu_increment"}}
	for capability, keys := range required {
		status := "passed"
		for _, key := range keys {
			found := false
			for _, m := range r.Metrics {
				if m.Key != key {
					continue
				}
				found = true
				if m.Status == "failed" {
					status = "failed"
				} else if m.Status != "passed" && status != "failed" {
					status = "insufficient_evidence"
				}
			}
			if !found && status != "failed" {
				status = "insufficient_evidence"
			}
		}
		r.CapabilityStatus[capability] = status
	}
	if !r.ProvenanceComplete {
		for capability, status := range r.CapabilityStatus {
			if status == "passed" {
				r.CapabilityStatus[capability] = "insufficient_evidence"
			}
		}
	}
	if r.CapabilityStatus["static"] == "passed" {
		for _, kind := range []string{"agent", "model", "mcp", "skill", "plugin", "tool"} {
			found := false
			for _, b := range r.Breakdowns {
				if b.Domain == "asset" && b.Dimension == "asset_type" && b.Name == kind && b.Counts.Expected > 0 && b.Counts.Unknown == 0 {
					found = true
				}
			}
			if !found {
				r.CapabilityStatus["static"] = "insufficient_evidence"
			}
		}
	}
}

// Match all reproducibility metadata before allowing a cross-mode CPU subtraction.
func evaluationKnownMetadata(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "unknown", "missing", "unavailable", "未记录", "未知":
		return false
	}
	return true
}
func evaluationTruthComparable(a, b EvaluationTruth, aDataset, bDataset string) bool {
	return a.ArtifactID != "" && b.ArtifactID != "" && a.SHA256 != "" && a.SHA256 == b.SHA256 && aDataset != "" && aDataset == bDataset && a.DatasetHash == aDataset && b.DatasetHash == bDataset
}
func evaluationStaticDataset(r EvaluationRun) string {
	if r.StaticDatasetHash != "" {
		return r.StaticDatasetHash
	}
	return r.DatasetHash
}
func EvaluationComparable(a, b EvaluationRun) bool {
	if a.ComparisonGroup == "" || a.ComparisonGroup != b.ComparisonGroup || a.StartedAt == "" || b.StartedAt == "" || a.FinishedAt == "" || b.FinishedAt == "" {
		return false
	}
	for _, pair := range [][2]string{{a.Platform, b.Platform}, {a.CodeVersion, b.CodeVersion}, {a.ConfigHash, b.ConfigHash}, {a.ImageDigest, b.ImageDigest}, {a.DatasetHash, b.DatasetHash}} {
		if !evaluationKnownMetadata(pair[0]) || pair[0] != pair[1] {
			return false
		}
	}
	if evaluationTruthComparable(a.RuntimeTruth, b.RuntimeTruth, a.DatasetHash, b.DatasetHash) {
		return true
	}
	return a.RuntimeTruth.ArtifactID == "" && b.RuntimeTruth.ArtifactID == "" && evaluationTruthComparable(a.StaticTruth, b.StaticTruth, evaluationStaticDataset(a), evaluationStaticDataset(b))
}
func ApplyEvaluationBaseline(run *EvaluationRun, baseline EvaluationRun) {
	if run.Mode != "action" || baseline.Mode != "baseline" || !evaluationTruthComparable(run.RuntimeTruth, baseline.RuntimeTruth, run.DatasetHash, baseline.DatasetHash) || run.Status != "completed" || baseline.Status != "completed" || !EvaluationComparable(*run, baseline) {
		return
	}
	for _, a := range run.Report.Distributions {
		if a.Kind != "cpu_pct" || a.Scope != "defense_chain" || a.Status != "complete" || a.P95 == nil {
			continue
		}
		for _, b := range baseline.Report.Distributions {
			if b.Kind != a.Kind || b.Scope != a.Scope || b.Basis != a.Basis || b.Status != "complete" || b.P95 == nil {
				continue
			}
			for n := range run.Report.Metrics {
				m := &run.Report.Metrics[n]
				if m.Key != "cpu_increment" {
					continue
				}
				v := *a.P95 - *b.P95
				m.Value = &v
				m.Status = "passed"
				m.Reason = "Baseline: " + baseline.ID + "; Action / Baseline samples: " + fmt.Sprint(a.Samples) + " / " + fmt.Sprint(b.Samples)
				if v > 5 {
					m.Status = "failed"
				}
			}
		}
	}
	setEvaluationCapabilityStatus(&run.Report)
}
