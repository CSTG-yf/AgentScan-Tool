from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from api.runtime_stack import runtime_stack_frames


def test_captures_a_real_application_frame_without_source_or_arguments():
    app_root = Path(__file__).resolve().parents[1]
    frames = runtime_stack_frames(app_root=app_root)
    frame = next(row for row in frames if row["file"] == "api/test_runtime_stack.py")
    assert frame["function"] == "test_captures_a_real_application_frame_without_source_or_arguments"
    assert frame["line"] > 0
    assert set(frame) == {"file", "function", "line"}
