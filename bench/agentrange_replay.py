"""Replay the full AgentRange arena and persist per-instance observations.

The arena remains the source of events and trajectories.  This adapter keeps
the private event objects in memory, exposes only a sanitized corpus, injects
trajectories through the llm-stub admin API, and records application HTTP
evidence without reading that admin API back.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, is_dataclass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import time
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import httpx

# Direct ``python bench/agentrange_replay.py`` puts ``bench`` on sys.path,
# rather than the repository root.  Add the root before importing benchmark
# helpers so the CLI and module invocation behave identically.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bench.agentrange_benchmark import (
    _fallback_ground_truth,
    git_commit,
    public_event_record,
    sha256_file,
    sha256_tree,
    write_jsonl,
)


RANGE_ROOT = ROOT / "task" / "AgentRange-player-full"
OPSPILOT = os.getenv("OPSPILOT_BASE", "http://localhost:8100")
LANGFLOW = os.getenv("LANGFLOW_BASE", "http://localhost:7860")
LLM_STUB = os.getenv("LLM_STUB_BASE", "http://localhost:8000")
DEFAULT_TIMEOUT = 30.0


class ReplayPreconditionError(RuntimeError):
    """The benchmark could not reach the intended attack request."""

_DECISION_KEYS = {
    "action",
    "decision",
    "raw_action",
    "verdict",
    "enforced_action",
    "hook_decision_action",
}
_TRACE_KEYS = {"trace_id", "traceid", "x-trace-id"}
_REQUEST_KEYS = {"request_id", "requestid", "x-request-id", "x-defenseclaw-request-id"}
_BLOCK_VALUES = {"block", "blocked", "deny", "denied", "reject", "rejected", "quarantine"}
_DECISIONS = {"allow", "alert", "confirm", "block"}


def _event_dict(event: Any) -> dict[str, Any]:
    if is_dataclass(event):
        return asdict(event)
    if isinstance(event, dict):
        return dict(event)
    return dict(vars(event))


def load_events(range_root: Path, seed: int, total: int, malicious_target: int) -> tuple[list[Any], Any]:
    """Load the arena generator without modifying or executing the full runner."""
    corpus_root = range_root / "corpus-generator"
    attack_root = range_root / "attack"
    generator_path = corpus_root / "generate.py"
    if not generator_path.exists():
        raise FileNotFoundError(f"missing arena generator: {generator_path}")
    old_path = list(sys.path)
    sys.path.insert(0, str(corpus_root))
    sys.path.insert(0, str(attack_root))
    try:
        module_name = f"agentrange_generate_{uuid4().hex}"
        spec = importlib.util.spec_from_file_location(module_name, generator_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load arena generator: {generator_path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        events = module.generate(seed=seed, total=total, malicious_target=malicious_target)
        return list(events), module
    finally:
        sys.path[:] = old_path


def detector_record(event: Any, public_record_fn: Any | None = None) -> dict[str, Any]:
    """Build a detector-facing row and remove nested exploit controls too."""
    record = public_event_record(event, public_record_fn)
    event_input = record.get("input")
    if isinstance(event_input, dict):
        event_input = dict(event_input)
        event_input.pop("exploit", None)
        event_input.pop("cmd", None)
        record["input"] = event_input
    return record


def _json_loads(response: httpx.Response) -> Any:
    try:
        return response.json()
    except (ValueError, json.JSONDecodeError):
        return None


def _walk(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def _normalize_decision(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip().lower().replace("_", "-")
    if value in _DECISIONS:
        return value
    if value in _BLOCK_VALUES:
        return "block"
    if value in {"needs-confirmation", "approval", "ask"}:
        return "confirm"
    if value in {"warn", "warning", "would-block"}:
        return "alert"
    return None


def response_evidence(response: httpx.Response) -> dict[str, Any]:
    """Extract transport and nested DefenseClaw evidence from one response."""
    body_bytes = response.content
    body = _json_loads(response)
    decision: str | None = "block" if response.status_code == 403 else None
    trace_id = None
    request_id = None
    inspect_latency = None
    phase = None
    raw_action = None

    for key, value in response.headers.items():
        lowered = key.lower()
        if lowered in _TRACE_KEYS and value:
            trace_id = value
        if lowered in _REQUEST_KEYS and value:
            request_id = value
        if lowered in {"x-defenseclaw-inspect-latency-ms", "x-inspect-latency-ms"}:
            try:
                inspect_latency = float(value)
            except ValueError:
                pass

    for item in _walk(body):
        for key, value in item.items():
            lowered = str(key).lower().replace("-", "_")
            if lowered in _DECISION_KEYS:
                candidate = _normalize_decision(value)
                if candidate == "block" or (candidate and decision not in {"block"}):
                    decision = candidate
                if lowered == "raw_action" and value is not None:
                    raw_action = str(value)
            elif lowered == "phase":
                if value is not None:
                    phase = str(value)
            elif lowered in _TRACE_KEYS or lowered == "trace_id":
                if isinstance(value, str) and value:
                    trace_id = value
            elif lowered in _REQUEST_KEYS or lowered == "request_id":
                if isinstance(value, str) and value:
                    request_id = value
            elif lowered in {"latency_ms", "inspect_latency_ms", "inspection_latency_ms"}:
                try:
                    inspect_latency = float(value)
                except (TypeError, ValueError):
                    pass

    text = body_bytes.decode("utf-8", errors="replace").lower()
    if decision is None and "defenseclaw" in text and any(token in text for token in ("block", "blocked", "denied")):
        decision = "block"
    if decision is None:
        decision = "allow" if 200 <= response.status_code < 300 else "unknown"
    return {
        "status": response.status_code,
        "decision": decision,
        "trace_id": trace_id,
        "request_id": request_id,
        "inspect_latency_ms": inspect_latency,
        "response_phase": phase,
        "response_raw_action": raw_action,
        "response_sha256": hashlib.sha256(body_bytes).hexdigest(),
        "response_bytes": len(body_bytes),
        "response_body": body,
    }


def _base_observation(instance_id: str, mode: str, started: float) -> dict[str, Any]:
    return {
        "instance_id": instance_id,
        "mode": mode,
        "decision": "unknown",
        "valid": True,
        "timeout": False,
        "business_success": None,
        "side_effect_reached": None,
        "side_effect_probe_status": "unknown",
        "side_effect_probe_refs": [],
        "status": None,
        "inspect_latency_ms": None,
        "e2e_latency_ms": round((time.perf_counter() - started) * 1000, 3),
        "error": None,
    }


def _apply_response(observation: dict[str, Any], response: httpx.Response, started: float) -> None:
    evidence = response_evidence(response)
    for key in (
        "status",
        "decision",
        "trace_id",
        "request_id",
        "inspect_latency_ms",
        "response_phase",
        "response_raw_action",
        "response_sha256",
        "response_bytes",
    ):
        value = evidence.get(key)
        if value is not None:
            observation[key] = value
    observation["e2e_latency_ms"] = round((time.perf_counter() - started) * 1000, 3)
    if response.status_code >= 400:
        observation["error"] = f"HTTP {response.status_code}"
    observation["business_success"] = 200 <= response.status_code < 300 and evidence["decision"] != "block"


def _apply_exception(observation: dict[str, Any], exc: Exception, started: float) -> None:
    response = getattr(exc, "response", None)
    if isinstance(response, httpx.Response):
        _apply_response(observation, response, started)
        observation["error"] = f"HTTP {response.status_code}"
        return
    observation["valid"] = False
    observation["timeout"] = isinstance(exc, httpx.TimeoutException)
    observation["business_success"] = None
    observation["error"] = f"{type(exc).__name__}: {exc}"
    observation["e2e_latency_ms"] = round((time.perf_counter() - started) * 1000, 3)


def _cat1_request(client: httpx.Client, event: dict[str, Any], token: str, range_root: Path) -> httpx.Response:
    attack_root = range_root / "attack"
    # The helpers are arena payload builders, not the frozen scenario runner.
    def load_helper(filename: str, name: str):
        path = attack_root / "cat1" / filename
        spec = importlib.util.spec_from_file_location(f"agentrange_{name}_{uuid4().hex}", path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load Cat1 helper: {path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    make_payload = load_helper("exploit_0770.py", "exploit_0770").make_payload
    make_upload = load_helper("exploit_5027.py", "exploit_5027").make_upload
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Instance-Id": str(event["instance_id"]),
        "X-Trace-Id": str(event["instance_id"]),
        "X-DefenseClaw-Trace-Id": str(event["instance_id"]),
        "X-DefenseClaw-Session-Id": str(event["instance_id"]),
    }
    exploit = event["input"].get("exploit")
    if exploit == "C1-A":
        request = make_payload(event["input"]["cmd"])
        return client.post(f"{LANGFLOW}{request['path']}", headers=headers, json=request["json"])
    upload = make_upload(f"/etc/cron.d/{event['instance_id']}", "* * * * * root id")
    return client.post(
        f"{LANGFLOW}{upload['path']}",
        headers=headers,
        params={"append": "true"},
        files={"file": (upload["filename"], upload["content"])},
    )


def _login(client: httpx.Client, username: str) -> str:
    response = client.post(f"{OPSPILOT}/login", json={"username": username})
    response.raise_for_status()
    payload = response.json()
    return str(payload["access_token"])


def _langflow_token(client: httpx.Client) -> str:
    response = client.get(f"{LANGFLOW}/api/v1/auto_login")
    if response.status_code != 200:
        raise ReplayPreconditionError(f"Langflow auto_login returned HTTP {response.status_code}")
    payload = _json_loads(response)
    token = payload.get("access_token") if isinstance(payload, dict) else None
    if not isinstance(token, str) or not token:
        raise ReplayPreconditionError("Langflow auto_login did not issue a token")
    return token


def inject_trajectories(trajectories: dict[str, list[dict[str, Any]]], timeout: float = DEFAULT_TIMEOUT) -> None:
    response = httpx.post(f"{LLM_STUB}/admin/trajectories", json={"trajectories": trajectories}, timeout=timeout)
    response.raise_for_status()


def clear_trajectories(timeout: float = DEFAULT_TIMEOUT) -> None:
    response = httpx.delete(f"{LLM_STUB}/admin/trajectories", timeout=timeout)
    response.raise_for_status()


def replay_events(
    events: list[Any],
    mode: str,
    only: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    range_root: Path = RANGE_ROOT,
    target_rate: float | None = None,
) -> list[dict[str, Any]]:
    selected = [event for event in events if not only or only == "all" or _event_dict(event).get("scenario") == only]
    observations: list[dict[str, Any]] = []
    tokens: dict[str, str] = {}
    langflow_token = None
    with httpx.Client(timeout=timeout) as client:
        schedule_start = time.perf_counter()
        for index, event_obj in enumerate(sorted(selected, key=lambda item: _event_dict(item).get("t", 0))):
            if target_rate is not None:
                delay = schedule_start + index / target_rate - time.perf_counter()
                if delay > 0:
                    time.sleep(delay)
            event = _event_dict(event_obj)
            started = time.perf_counter()
            observation = _base_observation(str(event["instance_id"]), mode, started)
            try:
                event_input = event.get("input") or {}
                if event_input.get("exploit"):
                    langflow_token = langflow_token or _langflow_token(client)
                    response = _cat1_request(client, event, langflow_token, range_root)
                    if response.status_code == 401:
                        # Long benchmark runs can outlive the Langflow token.
                        # Refresh once so token expiry is not recorded as an
                        # application failure or a detector miss.
                        langflow_token = _langflow_token(client)
                        response = _cat1_request(client, event, langflow_token, range_root)
                else:
                    actor = event.get("actor") or {}
                    username = str(actor.get("sub") or "")
                    tokens.setdefault(username, _login(client, username))
                    body = {"model": "opspilot-stub", "prompt": event_input.get("prompt", "")}
                    if event_input.get("skill"):
                        body["skill"] = event_input["skill"]

                    def send_run(token: str) -> httpx.Response:
                        headers = {
                            "Authorization": f"Bearer {token}",
                            "X-Instance-Id": str(event["instance_id"]),
                            "X-Trace-Id": str(event["instance_id"]),
                            "X-DefenseClaw-Trace-Id": str(event["instance_id"]),
                            "X-DefenseClaw-Session-Id": str(event["instance_id"]),
                        }
                        return client.post(f"{OPSPILOT}/run", headers=headers, json=body)

                    response = send_run(tokens[username])
                    if response.status_code == 401:
                        tokens[username] = _login(client, username)
                        response = send_run(tokens[username])
                _apply_response(observation, response, started)
            except ReplayPreconditionError as exc:
                observation["valid"] = False
                observation["error"] = f"precondition: {exc}"
                observation["e2e_latency_ms"] = round((time.perf_counter() - started) * 1000, 3)
            except Exception as exc:  # preserve one observation per event
                _apply_exception(observation, exc, started)
            observations.append(observation)
    return observations


def run(args: argparse.Namespace) -> int:
    output_dir = args.run_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    started_at = datetime.now(UTC).isoformat()
    process: dict[str, Any] = {
        "schema_version": 1,
        "run_id": output_dir.name,
        "mode": args.mode,
        "started_at": started_at,
        "range_root": str(args.range_root.resolve()),
        "trajectory_injected": False,
        "trajectory_cleared": False,
        "events": 0,
        "observations": 0,
    }
    try:
        events, generator = load_events(args.range_root.resolve(), args.seed, args.total, args.malicious_target)
        selected = [event for event in events if not args.only or args.only == "all" or _event_dict(event).get("scenario") == args.only]
        public_fn = getattr(generator, "public_record", None)
        public_rows = [detector_record(event, public_fn) for event in selected]
        ground_truth = [_fallback_ground_truth(event, public) for event, public in zip(selected, public_rows)]
        for row in ground_truth:
            row["run_id"] = output_dir.name
            row["mode"] = args.mode
        write_jsonl(output_dir / "public-corpus.jsonl", public_rows)
        write_jsonl(output_dir / "gt.jsonl", ground_truth)
        semantic_ground_truth = "\n".join(
            json.dumps(
                {key: value for key, value in row.items() if key not in {"run_id", "mode"}},
                ensure_ascii=False,
                sort_keys=True,
            )
            for row in ground_truth
        ).encode("utf-8")
        (output_dir / "run.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "run_id": output_dir.name,
                    "created_at": started_at,
                    "mode": args.mode,
                    "seed": args.seed,
                    "total": len(selected),
                    "malicious_target": sum(row["label"] == "malicious" for row in ground_truth),
                    "git_commit": git_commit(),
                    "arena_root": str(args.range_root.resolve()),
                    "arena_sha256": sha256_tree(args.range_root.resolve()),
                    "public_corpus_sha256": sha256_file(output_dir / "public-corpus.jsonl"),
                    "ground_truth_sha256": sha256_file(output_dir / "gt.jsonl"),
                    "ground_truth_semantic_sha256": hashlib.sha256(semantic_ground_truth).hexdigest(),
                    "forbidden_detector_inputs": ["/admin/trajectories", "scenario_id", "label", "gt.jsonl"],
                    "detection_input_contract": "public-corpus.jsonl plus application/system observations only",
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        process["events"] = len(selected)
        trajectories = {
            str(_event_dict(event)["instance_id"]): list(_event_dict(event).get("trajectory") or [])
            for event in selected
            if _event_dict(event).get("trajectory")
        }
        inject_trajectories(trajectories)
        process["trajectory_injected"] = True
        observations = replay_events(selected, args.mode, only=None, timeout=args.timeout, range_root=args.range_root.resolve(), target_rate=getattr(args, "target_rate", None))
        write_jsonl(output_dir / "observations.jsonl", observations)
        process["observations"] = len(observations)
        return_code = 0 if all(row.get("valid") is True for row in observations) else 1
    except Exception as exc:
        process["error"] = f"{type(exc).__name__}: {exc}"
        return_code = 2
    finally:
        try:
            clear_trajectories()
            process["trajectory_cleared"] = True
        except Exception as exc:
            process["trajectory_cleanup_error"] = f"{type(exc).__name__}: {exc}"
        process["finished_at"] = datetime.now(UTC).isoformat()
        (output_dir / "replay-process.json").write_text(json.dumps(process, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return return_code


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--mode", choices=("baseline", "observe", "action"), required=True)
    parser.add_argument("--range-root", type=Path, default=RANGE_ROOT)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--total", type=int, default=5200)
    parser.add_argument("--malicious-target", type=int, default=80)
    parser.add_argument("--only")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--target-rate", type=float, help="Maximum replay events per second")
    args = parser.parse_args()
    if args.target_rate is not None and args.target_rate <= 0:
        parser.error("--target-rate must be positive")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
