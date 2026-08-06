from dataclasses import dataclass, field


@dataclass
class Event:
    instance_id: str
    t: int
    kind: str
    scenario: str
    actor: dict | None
    input: dict
    trajectory: list[dict]
    malicious: bool
    evidence: dict = field(default_factory=dict)

