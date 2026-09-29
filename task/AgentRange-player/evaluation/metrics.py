"""Instance-level evaluation metrics with explicit evidence coverage.

The public replay corpus never carries labels. This module consumes private
truth and observations *after* replay; neither is sent to the AgentRange app.
Missing detection or side-effect evidence is unresolved, not a negative.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

LABELS = {"attack", "benign"}
EFFECTS = {"occurred", "prevented", "none", "unknown"}


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def summarize_instances(truth: list[dict[str, Any]], observations: list[dict[str, Any]]) -> dict[str, Any]:
    """Calculate only metrics supported by per-instance evidence.

    ``detected`` is tri-state: true/false/null. ``effect`` is an independently
    verified outcome, not a proxy verdict or HTTP status. Each observation
    must cite a detection ID or a complete negative query window before it
    can count toward a confusion-matrix cell. Attack prevention additionally requires a
    side-effect evidence reference and an enforced block decision.
    """
    truth_by_id: dict[str, dict[str, Any]] = {}
    for item in truth:
        instance_id = str(item.get("instance_id") or "").strip()
        label = item.get("label")
        if not instance_id or label not in LABELS or instance_id in truth_by_id:
            raise ValueError("truth requires unique instance_id and attack/benign label")
        truth_by_id[instance_id] = item

    observed_by_id: dict[str, dict[str, Any]] = {}
    for item in observations:
        instance_id = str(item.get("instance_id") or "").strip()
        if instance_id not in truth_by_id or instance_id in observed_by_id:
            raise ValueError("observation has unknown or duplicate instance_id")
        if item.get("detected") not in (True, False, None):
            raise ValueError("detected must be true, false, or null")
        if item.get("effect", "unknown") not in EFFECTS:
            raise ValueError("invalid side-effect outcome")
        observed_by_id[instance_id] = item

    counts: Counter[str] = Counter()
    rows: list[dict[str, Any]] = []
    for instance_id, item in truth_by_id.items():
        observation = observed_by_id.get(instance_id, {})
        label = item["label"]
        refs = observation.get("evidence_refs") or []
        raw_detected = observation.get("detected")
        has_detection_ref = any(isinstance(ref, str) and ref.startswith("detection:") for ref in refs)
        has_scope_ref = any(isinstance(ref, str) and (ref.startswith("event:") or ref.startswith("query:")) for ref in refs)
        detected = raw_detected if (
            (raw_detected is True and has_detection_ref)
            or (raw_detected is False and has_scope_ref and observation.get("detection_scope_complete") is True)
        ) else None
        cell = "unverified"
        if detected is not None:
            cell = ("TP" if detected else "FN") if label == "attack" else ("FP" if detected else "TN")
        counts[cell] += 1

        effect = observation.get("effect", "unknown")
        effect_ref = observation.get("effect_evidence_ref")
        enforced = observation.get("enforced_block") is True
        business_completed = observation.get("business_completed") is True
        if label == "attack":
            if effect_ref and effect == "prevented" and enforced:
                counts["effective_blocks"] += 1
            elif effect_ref and effect == "occurred":
                counts["attack_side_effects"] += 1
            else:
                counts["attack_effect_unverified"] += 1
        else:
            if effect_ref and effect == "none" and business_completed and not enforced:
                counts["normal_business_success"] += 1
            elif effect_ref and (effect == "prevented" or enforced):
                counts["normal_business_blocked"] += 1
            else:
                counts["normal_business_unverified"] += 1
        rows.append({
            "instance_id": instance_id,
            "scenario": item.get("scenario"),
            "label": label,
            "detection_cell": cell,
            "effect": effect,
            "effective_block": label == "attack" and bool(effect_ref and effect == "prevented" and enforced),
            "evidence_refs": refs,
            "effect_evidence_ref": effect_ref,
        })

    tp, fp, fn, tn = (counts[key] for key in ("TP", "FP", "FN", "TN"))
    attack_total = sum(item["label"] == "attack" for item in truth_by_id.values())
    benign_total = len(truth_by_id) - attack_total
    detection_complete = counts["unverified"] == 0
    return {
        "instances": rows,
        "counts": {key: counts[key] for key in (
            "TP", "FP", "FN", "TN", "unverified", "effective_blocks", "attack_side_effects",
            "attack_effect_unverified", "normal_business_success", "normal_business_blocked",
            "normal_business_unverified",
        )},
        "metrics": {
            "precision": _ratio(tp, tp + fp) if detection_complete else None,
            "recall": _ratio(tp, tp + fn) if detection_complete else None,
            "fpr": _ratio(fp, fp + tn) if detection_complete else None,
            "fnr": _ratio(fn, tp + fn) if detection_complete else None,
            "effective_block_rate": _ratio(counts["effective_blocks"], attack_total)
            if counts["attack_effect_unverified"] == 0 else None,
            "normal_business_success_rate": _ratio(counts["normal_business_success"], benign_total)
            if counts["normal_business_unverified"] == 0 else None,
        },
        "coverage": {
            "truth_instances": len(truth_by_id),
            "observed_instances": len(observed_by_id),
            "detection_verified": tp + fp + fn + tn,
            "effect_verified": attack_total + benign_total - counts["attack_effect_unverified"] - counts["normal_business_unverified"],
        },
    }
