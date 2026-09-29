import json
import argparse
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from pathlib import Path

from bench.agentrange_benchmark import (
    _confusion, _score_combined_defense_cpu, _score_host_gateway_cpu, prepare_all, prepare_run, score_run,
)
from bench.benchmark import summarize_modes
from bench.enrich_observations import enrich
from bench.resource_sampler import docker_stats, sample
from bench.side_effect_probes import c2_delta, evaluate_side_effects
from bench.live_replay import run as run_live_replay
from bench import live_replay_with_resources
from bench import agentrange_replay
from bench.merge_observation_run import merge as merge_observation_run


def write_replay_timing(run_dir: Path) -> None:
    (run_dir / "replay-process.json").write_text(json.dumps({
        "started_at": "2026-09-29T00:00:00+00:00",
        "finished_at": "2026-09-29T00:10:00+00:00",
    }), encoding="utf-8")


class AgentRangeBenchmarkTest(unittest.TestCase):
    def test_resource_wrapper_starts_host_sampler_with_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            args = argparse.Namespace(
                run_dir=Path(directory) / "action", range_root=Path("task/AgentRange-player-full"),
                mode="action", seed=1337, total=4, malicious_target=1, samples=10,
                interval_ms=500, only=None, target_rate=1.5,
                host_gateway_pid=16740, host_interval_ms=2000,
            )
            docker_sampler = MagicMock()
            host_sampler = MagicMock()
            docker_sampler.poll.return_value = None
            host_sampler.poll.return_value = None
            with patch.object(live_replay_with_resources, "sys", SimpleNamespace(executable="python", platform="win32")), \
                    patch.object(live_replay_with_resources.shutil, "which", return_value="pwsh"), \
                    patch.object(live_replay_with_resources.subprocess, "Popen", side_effect=[docker_sampler, host_sampler]) as spawn, \
                    patch.object(live_replay_with_resources.subprocess, "run", return_value=SimpleNamespace(returncode=0)):
                self.assertEqual(live_replay_with_resources.run(args), 0)
            host_command = spawn.call_args_list[1].args[0]
            self.assertIn("host_gateway_sampler.ps1", host_command[host_command.index("-File") + 1])
            self.assertEqual(host_command[host_command.index("-GatewayProcessId") + 1], "16740")
            docker_sampler.terminate.assert_called_once()
            host_sampler.terminate.assert_called_once()

    def test_host_gateway_cpu_requires_full_replay_window(self):
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            (run_dir / "run.json").write_text('{"mode":"action"}', encoding="utf-8")
            (run_dir / "replay-process.json").write_text(json.dumps({
                "started_at": "2026-09-29T00:00:00+00:00",
                "finished_at": "2026-09-29T00:00:10+00:00",
            }), encoding="utf-8")
            rows = [{
                "timestamp": f"2026-09-29T00:00:{second:02d}+00:00",
                "mode": "action", "process_start": "2026-09-28T00:00:00Z",
                "interval_seconds": 2, "logical_processors": 16,
                "cpu_host_pct": value, "cpu_core_pct": value * 16,
            } for second, value in ((2, 2.0), (4, 3.0), (6, 4.0), (8, 4.5), (10, 4.8))]
            output = run_dir / "host-gateway.jsonl"
            output.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
            report = _score_host_gateway_cpu(run_dir)
            self.assertEqual(report["status"], "complete")
            self.assertEqual(report["cpu_host_pct"]["p95"], 4.8)
            docker_rows = [{
                "timestamp": row["timestamp"], "mode": "action",
                "container": "defenseclaw-proxy", "cpu_pct": 16.0,
            } for row in rows]
            combined = _score_combined_defense_cpu(run_dir, docker_rows, report)
            self.assertEqual(combined["status"], "complete")
            self.assertEqual(combined["cpu_host_pct"]["p95"], 5.8)
            self.assertEqual(
                _score_combined_defense_cpu(run_dir, docker_rows[:1], report)["status"],
                "partial_window",
            )
            output.write_text("\n".join(json.dumps(row) for row in rows[3:]) + "\n", encoding="utf-8")
            partial = _score_host_gateway_cpu(run_dir)
            self.assertEqual(partial["status"], "partial_window")
            self.assertEqual(_score_combined_defense_cpu(run_dir, docker_rows, partial)["status"], "partial_window")
            output.write_text("\n".join(json.dumps({**row, "process_start": None}) for row in rows) + "\n", encoding="utf-8")
            self.assertEqual(_score_host_gateway_cpu(run_dir)["status"], "partial_window")
            output.write_text("\n".join(json.dumps({**row, "timestamp": row["timestamp"].removesuffix("+00:00")}) for row in rows) + "\n", encoding="utf-8")
            self.assertEqual(_score_host_gateway_cpu(run_dir)["status"], "invalid_samples")

    def test_action_requires_enforced_block_not_would_block(self):
        truth = [{"instance_id": "attack", "label": "malicious", "scenario_id": "C2-A"}]
        observation = {
            "instance_id": "attack",
            "decision": "allow",
            "raw_action": "block",
            "would_block": True,
            "detector_block_evidence": [{"enforced": False, "would_block": True}],
            "valid": True,
            "timeout": False,
            "business_success": False,
            "side_effect_reached": False,
            "e2e_latency_ms": 12,
        }
        action = _confusion(truth, [observation], "action")
        observe = _confusion(truth, [observation], "observe")
        self.assertEqual(action["counts"]["fn"], 1)
        self.assertEqual(observe["counts"]["tp"], 1)
        self.assertEqual(_confusion(truth, [{**observation, "decision": "block"}], "action")["counts"]["fn"], 1)
        self.assertEqual(
            _confusion(truth, [{**observation, "response_raw_action": "block", "decision": "block"}], "action")["counts"]["tp"],
            1,
        )

    def test_differential_merge_requires_matching_public_subset(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base, replacement, output = (root / name for name in ("base", "replacement", "merged"))
            base.mkdir()
            replacement.mkdir()
            manifest = {"arena_sha256": "arena", "mode": "action", "seed": 1337}
            for folder in (base, replacement):
                (folder / "run.json").write_text(json.dumps(manifest), encoding="utf-8")
            truth = [
                {"instance_id": "A", "label": "benign", "input_sha256": "a", "run_id": "base"},
                {"instance_id": "B", "label": "malicious", "input_sha256": "b", "run_id": "base"},
            ]
            public = [
                {"instance_id": "A", "input": {"prompt": "ordinary"}},
                {"instance_id": "B", "input": {"prompt": "attack"}},
            ]
            def write_rows(folder, name, rows):
                (folder / name).write_text(
                    "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8"
                )
            write_rows(base, "gt.jsonl", truth)
            write_rows(base, "public-corpus.jsonl", public)
            write_rows(base, "observations.jsonl", [
                {"instance_id": "A", "decision": "allow"},
                {"instance_id": "B", "decision": "allow"},
            ])
            write_rows(replacement, "gt.jsonl", [dict(truth[1], run_id="replacement")])
            write_rows(replacement, "public-corpus.jsonl", [public[1]])
            write_rows(replacement, "observations.jsonl", [{"instance_id": "B", "decision": "block"}])
            result = merge_observation_run(base, replacement, output)
            self.assertEqual(result["replacement_instances"], 1)
            merged = [json.loads(line) for line in (output / "observations.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual({row["instance_id"]: row["decision"] for row in merged}, {"A": "allow", "B": "block"})
            with self.assertRaises(FileExistsError):
                merge_observation_run(base, replacement, output)

            write_rows(replacement, "public-corpus.jsonl", [{"instance_id": "B", "input": {"prompt": "changed"}}])
            with self.assertRaisesRegex(ValueError, "public corpus mismatch"):
                merge_observation_run(base, replacement, root / "invalid")

    def test_langflow_login_failure_invalidates_attack_observation(self):
        event = {"instance_id": "C1-A-1", "t": 0, "input": {"exploit": "C1-A"}}
        with patch.object(
            agentrange_replay, "_langflow_token",
            side_effect=agentrange_replay.ReplayPreconditionError("Langflow auto_login returned HTTP 403"),
        ):
            observations = agentrange_replay.replay_events([event], "action")
        self.assertEqual(len(observations), 1)
        self.assertFalse(observations[0]["valid"])
        self.assertIn("precondition", observations[0]["error"])
        self.assertEqual(observations[0]["decision"], "unknown")

    def test_unknown_side_effect_is_not_scored_as_false_negative(self):
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "action"
            prepare_run(run_dir, total=2, malicious_target=1, mode="action")
            truth = [json.loads(line) for line in (run_dir / "gt.jsonl").read_text(encoding="utf-8").splitlines()]
            observations = [
                {
                    "instance_id": row["instance_id"],
                    "decision": "allow",
                    "valid": True,
                    "timeout": False,
                    "side_effect_reached": None if row["label"] == "malicious" else False,
                    "business_success": row["label"] == "benign",
                    "e2e_latency_ms": 12,
                }
                for row in truth
            ]
            (run_dir / "observations.jsonl").write_text(
                "\n".join(json.dumps(row) for row in observations) + "\n", encoding="utf-8"
            )
            report = score_run(run_dir)
            self.assertEqual(report["overall"]["counts"]["unknown"], 1)
            self.assertEqual(report["overall"]["counts"]["fn"], 0)
            self.assertFalse(report["acceptance"]["evidence_complete"])

    def test_legacy_summary_does_not_score_after_snapshot_as_cpu_increment(self):
        with tempfile.TemporaryDirectory() as directory:
            result_dir = Path(directory)
            (result_dir / "baseline.json").write_text(
                json.dumps({"resources": {"after": {"rows": [{"CPUPerc": "1%"}]}}}),
                encoding="utf-8",
            )
            (result_dir / "action.json").write_text(
                json.dumps({
                    "resources": {"after": {"rows": [{"CPUPerc": "10%"}]}},
                    "metrics": {"recall": 1.0, "fpr": 0.0, "normal_success_rate": 1.0},
                }),
                encoding="utf-8",
            )
            summary = summarize_modes(result_dir)
            self.assertEqual(summary["modes"]["action"]["cpu_comparison_status"], "legacy_snapshot_unverified")
            self.assertIsNone(summary["modes"]["action"]["cpu_increment_pct"])
            self.assertFalse(summary["acceptance"]["cpu_increment_lte_5pct"])

    def test_summary_reuses_scored_p95_resource_report_and_partial_status(self):
        with tempfile.TemporaryDirectory() as directory:
            result_dir = Path(directory)
            (result_dir / "baseline.json").write_text(json.dumps({"resources": {}}), encoding="utf-8")
            (result_dir / "action.json").write_text(
                json.dumps({
                    "resources": {
                        "cpu_p95_pct": 4.7,
                        "cpu_increment_statistic": "p95",
                        "cpu_increment_method": "max per-container p95(action) - p95(baseline)",
                        "cpu_increment_pct": 2.15,
                        "cpu_increment_by_container": {"postgres": 2.15},
                        "baseline": {"status": "partial_container_overlap"},
                    },
                    "metrics": {"recall": 1.0, "fpr": 0.0, "normal_success_rate": 1.0},
                }),
                encoding="utf-8",
            )
            summary = summarize_modes(result_dir)
            action = summary["modes"]["action"]
            self.assertEqual(action["cpu_increment_statistic"], "p95")
            self.assertEqual(action["cpu_increment_pct"], 2.15)
            self.assertEqual(action["cpu_increment_by_container"], {"postgres": 2.15})
            self.assertEqual(action["cpu_comparison_status"], "partial_container_overlap")
            self.assertFalse(summary["acceptance"]["cpu_increment_lte_5pct"])

    def test_summary_normalizes_score_report_overall_metrics(self):
        with tempfile.TemporaryDirectory() as directory:
            result_dir = Path(directory)
            score_report = {
                "overall": {
                    "counts": {"tp": 8, "fp": 0, "tn": 12, "fn": 0, "unknown": 0},
                    "metrics": {"recall": 1.0, "fpr": 0.0},
                    "normal_business": {"success_rate": 1.0},
                    "latency_ms": {"p95": 42.0},
                },
                "resources": {
                    "cpu_p95_pct": 2.0,
                    "cpu_increment_statistic": "p95",
                    "cpu_increment_pct": 1.0,
                    "baseline": {"status": "complete"},
                },
            }
            (result_dir / "action.json").write_text(json.dumps(score_report), encoding="utf-8")
            summary = summarize_modes(result_dir)
            action = summary["modes"]["action"]
            self.assertEqual(action["counts"]["tp"], 8)
            self.assertEqual(action["metrics"]["recall"], 1.0)
            self.assertEqual(action["metrics"]["normal_success_rate"], 1.0)
            self.assertEqual(action["inspect_latency_ms"]["p95"], 42.0)
            self.assertTrue(summary["acceptance"]["cpu_increment_lte_5pct"])

    def test_summary_treats_missing_inspect_p95_as_unverified(self):
        with tempfile.TemporaryDirectory() as directory:
            result_dir = Path(directory)
            (result_dir / "action.json").write_text(
                json.dumps({
                    "overall": {"metrics": {"recall": 1.0, "fpr": 0.0, "normal_success_rate": 1.0}},
                    "inspect_latency_ms": {"p95": None},
                    "resources": {},
                }),
                encoding="utf-8",
            )
            summary = summarize_modes(result_dir)
            self.assertFalse(summary["acceptance"]["inspect_p95_lt_1000ms"])

    def test_enrich_promotes_nested_runtime_block_over_outer_http_allow(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_dir = root / "action"
            run_dir.mkdir()
            (run_dir / "gt.jsonl").write_text(
                json.dumps(
                    {
                        "instance_id": "C2-A-1",
                        "label": "malicious",
                        "expected_side_effects": ["cross_tenant_customer_rows"],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (run_dir / "observations.jsonl").write_text(
                json.dumps(
                    {
                        "instance_id": "C2-A-1",
                        "mode": "action",
                        "decision": "allow",
                        "valid": True,
                        "timeout": False,
                        "side_effect_reached": None,
                        "business_success": True,
                        "e2e_latency_ms": 200,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            db_path = root / "audit.db"
            connection = sqlite3.connect(db_path)
            connection.execute("CREATE TABLE audit_events (timestamp TEXT, session_id TEXT, action TEXT, structured_json TEXT)")
            connection.execute(
                "INSERT INTO audit_events VALUES (?, ?, ?, ?)",
                (
                    "2026-09-28T00:00:01Z",
                    "C2-A-1",
                    "agentrange-runtime-post",
                    json.dumps(
                        {
                            "instance_id": "C2-A-1",
                            "mode": "action",
                            "stage": "post",
                            "latency_ms": 42,
                            "destination": "llm-stub",
                            "decision": "block",
                            "severity": "CRITICAL",
                            "reason": "matched: AUTH-TENANT-SCOPE",
                        }
                    ),
                ),
            )
            connection.commit()
            connection.close()

            enrich(run_dir, db_path, "action")
            observation = json.loads((run_dir / "observations.jsonl").read_text(encoding="utf-8"))
            self.assertEqual(observation["decision"], "block")
            self.assertEqual(observation["transport_decision"], "allow")
            self.assertEqual(observation["detector_block_evidence"][0]["severity"], "CRITICAL")
            self.assertFalse(observation["side_effect_reached"])
            self.assertEqual(observation["side_effect_probe_status"], "complete")
            self.assertEqual(observation["inspect_latency_ms"], 42.0)

    def test_cat1_replay_uses_full_arena_public_shape(self):
        runner_root = Path(__file__).resolve().parents[1] / "task" / "AgentRange-player-full" / "scenario-runner"
        sys.path.insert(0, str(runner_root))
        try:
            from runner import plan_actions

            actions = plan_actions(
                [
                    {
                        "instance_id": "C1-A-0",
                        "t": 0,
                        "input": {"exploit": "C1-A", "cmd": "python -c pass"},
                    }
                ]
            )
        finally:
            sys.path.remove(str(runner_root))
        self.assertEqual(actions[0]["instance_id"], "C1-A-0")
        self.assertEqual(actions[0]["target"], "langflow")
        self.assertEqual(actions[0]["exploit"], "C1-A")

    @patch("bench.live_replay._docker_available", return_value=(False, "daemon unavailable"))
    def test_live_replay_records_environment_blocker(self, _docker):
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "action"
            status = run_live_replay(argparse.Namespace(run_dir=run_dir, mode="action", range_root=Path("task/AgentRange-player-full"), seed=1337, total=4, malicious_target=1, only=None))
            self.assertEqual(status, 2)
            process = json.loads((run_dir / "replay-process.json").read_text(encoding="utf-8"))
            self.assertFalse(process["docker_available"])
            self.assertEqual(process["error"], "daemon unavailable")

    @patch("bench.live_replay.subprocess.run")
    @patch("bench.live_replay._docker_available", return_value=(True, "29.8.0"))
    def test_live_replay_passes_mode_to_external_harness(self, _docker, run):
        run.return_value.returncode = 0
        run.return_value.stdout = ""
        run.return_value.stderr = ""
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "observe"
            status = run_live_replay(argparse.Namespace(run_dir=run_dir, mode="observe", range_root=Path("task/AgentRange-player-full"), seed=1337, total=4, malicious_target=1, only=None))
        self.assertEqual(status, 0)
        command = run.call_args.args[0]
        self.assertEqual(command[command.index("--mode") + 1], "observe")

    def test_prepare_all_reuses_identical_public_corpus(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "runs"
            result = prepare_all(root, total=12, malicious_target=3)
            self.assertEqual(set(result["runs"]), {"baseline", "observe", "action"})
            hashes = {item["public_corpus_sha256"] for item in result["runs"].values()}
            self.assertEqual(len(hashes), 1)
            truth_hashes = {item["ground_truth_semantic_sha256"] for item in result["runs"].values()}
            self.assertEqual(len(truth_hashes), 1)
            self.assertEqual(result["ground_truth_semantic_sha256"], truth_hashes.pop())

    @patch("bench.resource_sampler.subprocess.run")
    def test_resource_sampler_parses_docker_stats(self, run):
        run.return_value.returncode = 0
        run.return_value.stdout = '{"Name":"mcp","CPUPerc":"1.25%","MemUsage":"2MiB / 4GiB","MemPerc":"0.05%"}\n'
        run.return_value.stderr = ""
        self.assertEqual(docker_stats(), [{"container": "mcp", "cpu_pct": 1.25, "memory_usage": "2MiB / 4GiB", "memory_pct": 0.05}])

    @patch("bench.resource_sampler.docker_stats")
    def test_resource_sampler_serializes_concurrent_appends(self, stats):
        stats.return_value = [{"container": "mcp", "cpu_pct": 1.25, "memory_usage": None, "memory_pct": None}]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "resources.jsonl"
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [
                    executor.submit(sample, output, mode=mode, samples=8, interval_ms=0)
                    for mode in ("baseline", "action")
                ]
                for future in futures:
                    self.assertEqual(future.result(), 0)
            rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(rows), 16)
            self.assertEqual({row["mode"] for row in rows}, {"baseline", "action"})

    def test_resource_sampler_serializes_separate_processes(self):
        worker = (
            "from pathlib import Path; "
            "import bench.resource_sampler as s; "
            "s.docker_stats = lambda containers=None: [{{\"container\": \"mcp\", \"cpu_pct\": 1.25, \"memory_usage\": None, \"memory_pct\": None}}]; "
            "s.sample(Path({output}), mode={mode}, samples=8, interval_ms=0)"
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "resources.jsonl"
            processes = [
                subprocess.Popen(
                    [
                        sys.executable,
                        "-c",
                        worker.format(output=json.dumps(str(output)), mode=json.dumps(mode)),
                    ],
                    cwd=Path(__file__).resolve().parents[1],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                for mode in ("baseline", "action")
            ]
            for process in processes:
                stdout, stderr = process.communicate(timeout=30)
                self.assertEqual(process.returncode, 0, (stdout, stderr))
            rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(rows), 16)
            self.assertEqual({row["mode"] for row in rows}, {"baseline", "action"})

    def test_side_effect_probe_marks_unavailable_as_unknown(self):
        self.assertEqual(c2_delta({"available": True, "count": 2}, {"available": True, "count": 3})["new_receipts"], 1)
        result = evaluate_side_effects(
            {"expected_side_effects": ["sensitive_data_egress"]},
            c2_before={"available": False},
            c2_after={"available": False},
        )
        self.assertIsNone(result["side_effect_reached"])
        self.assertEqual(result["side_effect_probe_status"], "unknown")

    def test_prepare_separates_public_corpus_and_ground_truth(self):
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            manifest = prepare_run(run_dir, total=32, malicious_target=8)
            public_rows = [json.loads(line) for line in (run_dir / "public-corpus.jsonl").read_text(encoding="utf-8").splitlines()]
            ground_truth = [json.loads(line) for line in (run_dir / "gt.jsonl").read_text(encoding="utf-8").splitlines()]

            self.assertEqual(manifest["total"], 32)
            self.assertEqual(len(public_rows), len(ground_truth))
            self.assertTrue(all(not {"scenario", "kind", "malicious", "evidence", "trajectory"}.intersection(row) for row in public_rows))
            self.assertTrue(all(not {"exploit", "cmd"}.intersection(row.get("input", {})) for row in public_rows))
            self.assertEqual({row["scenario_id"] for row in ground_truth if row["label"] == "benign"}, {"normal"})

    def test_prepare_all_full_arena_sanitizes_public_fallback_truth_and_distribution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "runs"
            result = prepare_all(root, total=70, malicious_target=14)
            action_dir = root / "action"
            public_rows = [json.loads(line) for line in (action_dir / "public-corpus.jsonl").read_text(encoding="utf-8").splitlines()]
            ground_truth = [json.loads(line) for line in (action_dir / "gt.jsonl").read_text(encoding="utf-8").splitlines()]

            self.assertTrue(str(result["runs"]["action"]["arena_root"]).endswith("task\\AgentRange-player-full"))
            self.assertEqual(len(public_rows), 70)
            self.assertEqual(len(ground_truth), 70)
            forbidden = {"scenario", "scenario_id", "label", "malicious", "kind", "evidence", "trajectory"}
            self.assertTrue(all(not forbidden.intersection(row) for row in public_rows))
            self.assertEqual(sum(row["label"] == "malicious" for row in ground_truth), 14)
            self.assertEqual(sum(row["label"] == "benign" for row in ground_truth), 56)
            self.assertEqual(Counter(row["scenario_id"] for row in ground_truth if row["label"] == "malicious"), Counter({"C2-B": 4, "C1-A": 2, "C1-B": 2, "C2-A": 2, "C2-C": 2, "C2-D": 2}))
            self.assertTrue(all(row.get("input_sha256") for row in ground_truth))
            self.assertEqual(len({item["public_corpus_sha256"] for item in result["runs"].values()}), 1)
            self.assertEqual(len({item["ground_truth_semantic_sha256"] for item in result["runs"].values()}), 1)
            self.assertEqual(result["ground_truth_semantic_sha256"], next(iter({item["ground_truth_semantic_sha256"] for item in result["runs"].values()})))

    def test_score_requires_observation_and_calculates_confusion(self):
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            prepare_run(run_dir, total=16, malicious_target=4)
            truth = [json.loads(line) for line in (run_dir / "gt.jsonl").read_text(encoding="utf-8").splitlines()]
            observations = [
                {
                    "instance_id": row["instance_id"],
                    "decision": "block" if row["label"] == "malicious" else "allow",
                    "response_raw_action": "block" if row["label"] == "malicious" else None,
                    "valid": True,
                    "timeout": False,
                    "side_effect_reached": False,
                    "business_success": row["label"] == "benign",
                    "e2e_latency_ms": 12,
                    "inspect_latency_ms": 8,
                }
                for row in truth
            ]
            (run_dir / "observations.jsonl").write_text("\n".join(json.dumps(row) for row in observations) + "\n", encoding="utf-8")
            resources = [
                {"timestamp": "2026-09-28T00:00:00Z", "mode": "baseline", "container": "mcp", "cpu_pct": 0.5},
                {"timestamp": "2026-09-28T00:00:01Z", "mode": "action", "container": "mcp", "cpu_pct": 2.0},
            ]
            (run_dir / "resources.jsonl").write_text("\n".join(json.dumps(row) for row in resources) + "\n", encoding="utf-8")
            report = score_run(run_dir)
            self.assertEqual(report["overall"]["counts"]["tp"], 4)
            self.assertEqual(report["overall"]["counts"]["tn"], 12)
            self.assertEqual(report["overall"]["counts"]["unknown"], 0)
            self.assertEqual(report["overall"]["metrics"]["recall"], 1.0)
            self.assertEqual(report["overall"]["normal_business"]["success_rate"], 1.0)
            self.assertEqual(report["resources"]["cpu_increment_by_container"]["mcp"], 1.5)
            self.assertTrue(report["acceptance"]["inspect_p95_lt_1000ms"])
            self.assertTrue(report["acceptance"]["inspect_latency_coverage_1"])
            self.assertFalse(report["acceptance"]["host_gateway_cpu_p95_lte_5pct"])
            self.assertFalse(report["acceptance"]["combined_defense_cpu_p95_lte_5pct"])
            observations[0].pop("inspect_latency_ms")
            (run_dir / "observations.jsonl").write_text("\n".join(json.dumps(row) for row in observations) + "\n", encoding="utf-8")
            self.assertFalse(score_run(run_dir)["acceptance"]["inspect_latency_coverage_1"])

    def test_score_action_uses_sibling_baseline_window(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "runs"
            baseline_dir = root / "baseline"
            action_dir = root / "action"
            prepare_run(baseline_dir, total=4, malicious_target=1, mode="baseline")
            prepare_run(action_dir, total=4, malicious_target=1, mode="action")
            truth = [json.loads(line) for line in (action_dir / "gt.jsonl").read_text(encoding="utf-8").splitlines()]
            observations = [
                {
                    "instance_id": row["instance_id"],
                    "decision": "block" if row["label"] == "malicious" else "allow",
                    "valid": True,
                    "timeout": False,
                    "side_effect_reached": False,
                    "business_success": row["label"] == "benign",
                    "e2e_latency_ms": 12,
                }
                for row in truth
            ]
            (action_dir / "observations.jsonl").write_text("\n".join(json.dumps(row) for row in observations) + "\n", encoding="utf-8")
            (baseline_dir / "resources.jsonl").write_text(
                "\n".join(json.dumps({"mode": "baseline", "container": "mcp", "cpu_pct": value}) for value in (0.5, 1.0)) + "\n",
                encoding="utf-8",
            )
            (action_dir / "resources.jsonl").write_text(
                "\n".join(json.dumps({"mode": "action", "container": "mcp", "cpu_pct": value}) for value in (2.0, 3.0)) + "\n",
                encoding="utf-8",
            )
            self.assertEqual(score_run(action_dir)["resources"]["baseline"]["status"], "throughput_unverified")
            write_replay_timing(baseline_dir)
            write_replay_timing(action_dir)
            report = score_run(action_dir)
            self.assertEqual(report["resources"]["baseline"]["status"], "complete")
            self.assertEqual(report["resources"]["baseline"]["run_dir"], str(baseline_dir.resolve()))
            self.assertEqual(report["resources"]["cpu_increment_by_container"]["mcp"], 2.0)
            self.assertTrue(report["acceptance"]["cpu_increment_lte_5pct"])

    def test_score_rejects_cpu_comparison_with_different_replay_rates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline_dir = root / "baseline"
            action_dir = root / "action"
            baseline_dir.mkdir()
            action_dir.mkdir()
            manifest = {"seed": 1, "total": 100, "malicious_target": 1,
                        "ground_truth_semantic_sha256": "same", "arena_sha256": "same"}
            for folder, mode, minutes in ((baseline_dir, "baseline", 10), (action_dir, "action", 30)):
                (folder / "run.json").write_text(json.dumps({**manifest, "mode": mode}), encoding="utf-8")
                (folder / "replay-process.json").write_text(json.dumps({
                    "started_at": "2026-09-29T00:00:00+00:00",
                    "finished_at": f"2026-09-29T00:{minutes:02d}:00+00:00",
                }), encoding="utf-8")
                (folder / "resources.jsonl").write_text(json.dumps({
                    "mode": mode, "container": "mcp", "cpu_pct": 1.0,
                }) + "\n", encoding="utf-8")
            from bench.agentrange_benchmark import _score_resources, read_jsonl
            result = _score_resources(action_dir, read_jsonl(action_dir / "resources.jsonl"),
                                      baseline_run_dir=baseline_dir, run_mode="action")
            self.assertEqual(result["baseline"]["status"], "throughput_mismatch")
            self.assertEqual(result["baseline"]["throughput_ratio"], 0.333)
            self.assertIsNone(result["cpu_increment_pct"])

    def test_score_cpu_uses_symmetric_p95_instead_of_action_max(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "runs"
            baseline_dir = root / "baseline"
            action_dir = root / "action"
            prepare_run(baseline_dir, total=2, malicious_target=1, mode="baseline")
            prepare_run(action_dir, total=2, malicious_target=1, mode="action")
            truth = [json.loads(line) for line in (action_dir / "gt.jsonl").read_text(encoding="utf-8").splitlines()]
            observations = [
                {
                    "instance_id": row["instance_id"],
                    "decision": "block" if row["label"] == "malicious" else "allow",
                    "valid": True,
                    "timeout": False,
                    "side_effect_reached": False,
                    "business_success": row["label"] == "benign",
                    "e2e_latency_ms": 12,
                }
                for row in truth
            ]
            (action_dir / "observations.jsonl").write_text("\n".join(json.dumps(row) for row in observations) + "\n", encoding="utf-8")
            baseline_values = [1.0] * 20
            action_values = [2.0] * 19 + [100.0]
            (baseline_dir / "resources.jsonl").write_text(
                "\n".join(json.dumps({"mode": "baseline", "container": "mcp", "cpu_pct": value}) for value in baseline_values) + "\n",
                encoding="utf-8",
            )
            (action_dir / "resources.jsonl").write_text(
                "\n".join(json.dumps({"mode": "action", "container": "mcp", "cpu_pct": value}) for value in action_values) + "\n",
                encoding="utf-8",
            )
            write_replay_timing(baseline_dir)
            write_replay_timing(action_dir)
            report = score_run(action_dir)
            self.assertEqual(report["resources"]["cpu_increment_statistic"], "p95")
            self.assertEqual(report["resources"]["cpu_increment_by_container"]["mcp"], 1.0)
            self.assertEqual(report["resources"]["action_by_container"]["mcp"]["max_pct"], 100.0)

    def test_score_cpu_marks_added_action_containers_partial(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "runs"
            baseline_dir = root / "baseline"
            action_dir = root / "action"
            prepare_run(baseline_dir, total=2, malicious_target=1, mode="baseline")
            prepare_run(action_dir, total=2, malicious_target=1, mode="action")
            truth = [json.loads(line) for line in (action_dir / "gt.jsonl").read_text(encoding="utf-8").splitlines()]
            (action_dir / "observations.jsonl").write_text(
                "\n".join(json.dumps({
                    "instance_id": row["instance_id"], "decision": "block" if row["label"] == "malicious" else "allow",
                    "valid": True, "timeout": False, "side_effect_reached": False,
                    "business_success": row["label"] == "benign", "e2e_latency_ms": 12,
                }) for row in truth) + "\n",
                encoding="utf-8",
            )
            (baseline_dir / "resources.jsonl").write_text(json.dumps({"mode": "baseline", "container": "mcp", "cpu_pct": 1.0}) + "\n", encoding="utf-8")
            (action_dir / "resources.jsonl").write_text(
                "\n".join(json.dumps({"mode": "action", "container": container, "cpu_pct": 2.0}) for container in ("mcp", "new-sidecar")) + "\n",
                encoding="utf-8",
            )
            write_replay_timing(baseline_dir)
            write_replay_timing(action_dir)
            report = score_run(action_dir)
            self.assertEqual(report["resources"]["baseline"]["status"], "partial_container_overlap")
            self.assertEqual(report["resources"]["cpu_increment_pct"], 1.0)
            self.assertFalse(report["acceptance"]["cpu_increment_lte_5pct"])
            (action_dir / "differential-merge.json").write_text("{}", encoding="utf-8")
            merged_report = score_run(action_dir)
            self.assertEqual(merged_report["resources"]["baseline"]["status"], "differential_merge_unverified")
            self.assertIsNone(merged_report["resources"]["cpu_increment_pct"])
            self.assertFalse(merged_report["acceptance"]["cpu_increment_lte_5pct"])

    def test_score_does_not_infer_cpu_baseline_from_action_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "action"
            prepare_run(run_dir, total=2, malicious_target=1, mode="action")
            truth = [json.loads(line) for line in (run_dir / "gt.jsonl").read_text(encoding="utf-8").splitlines()]
            observations = [
                {
                    "instance_id": row["instance_id"],
                    "decision": "block" if row["label"] == "malicious" else "allow",
                    "valid": True,
                    "timeout": False,
                    "side_effect_reached": False,
                    "business_success": row["label"] == "benign",
                    "e2e_latency_ms": 12,
                }
                for row in truth
            ]
            (run_dir / "observations.jsonl").write_text("\n".join(json.dumps(row) for row in observations) + "\n", encoding="utf-8")
            (run_dir / "resources.jsonl").write_text(
                json.dumps({"mode": "action", "container": "mcp", "cpu_pct": 2.0, "baseline_cpu_pct": 0.0}) + "\n",
                encoding="utf-8",
            )
            report = score_run(run_dir)
            self.assertEqual(report["resources"]["baseline"]["status"], "missing")
            self.assertIsNone(report["resources"]["cpu_increment_pct"])
            self.assertFalse(report["acceptance"]["cpu_increment_lte_5pct"])

    def test_score_rejects_baseline_from_different_corpus(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "runs"
            baseline_dir = root / "baseline"
            action_dir = root / "action"
            prepare_run(baseline_dir, seed=7, total=4, malicious_target=1, mode="baseline")
            prepare_run(action_dir, seed=1337, total=4, malicious_target=1, mode="action")
            truth = [json.loads(line) for line in (action_dir / "gt.jsonl").read_text(encoding="utf-8").splitlines()]
            observations = [
                {
                    "instance_id": row["instance_id"],
                    "decision": "block" if row["label"] == "malicious" else "allow",
                    "valid": True,
                    "timeout": False,
                    "side_effect_reached": False,
                    "business_success": row["label"] == "benign",
                    "e2e_latency_ms": 12,
                }
                for row in truth
            ]
            (action_dir / "observations.jsonl").write_text("\n".join(json.dumps(row) for row in observations) + "\n", encoding="utf-8")
            (baseline_dir / "resources.jsonl").write_text(json.dumps({"mode": "baseline", "container": "mcp", "cpu_pct": 0.5}) + "\n", encoding="utf-8")
            (action_dir / "resources.jsonl").write_text(json.dumps({"mode": "action", "container": "mcp", "cpu_pct": 2.0}) + "\n", encoding="utf-8")
            report = score_run(action_dir)
            self.assertEqual(report["resources"]["baseline"]["status"], "manifest_mismatch")
            self.assertEqual(report["resources"]["baseline"]["manifest_compatibility"], "manifest_mismatch")
            self.assertIsNone(report["resources"]["cpu_increment_pct"])
            self.assertFalse(report["acceptance"]["cpu_increment_lte_5pct"])


if __name__ == "__main__":
    unittest.main()
