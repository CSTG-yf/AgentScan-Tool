import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest


spec = importlib.util.spec_from_file_location("agentrange_integrity", Path(__file__).with_name("check.py"))
integrity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(integrity)


class FixtureIntegrityTest(unittest.TestCase):
    def test_missing_skill_restored_and_modified_skill_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(integrity.ROOT / "integrity" / "baseline", root / "integrity" / "baseline")
            shutil.copytree(root / "integrity" / "baseline" / "skills", root / "skills")
            missing = root / "skills" / "meeting-summary" / "SKILL.md"
            missing.unlink()

            with self.assertRaisesRegex(ValueError, "missing fixture skills"):
                integrity.check(root, repair=False, quarantine_root=None)

            restored = integrity.check(root, repair=True, quarantine_root=None)
            self.assertEqual(restored, ["skills/meeting-summary/SKILL.md"])
            self.assertEqual(integrity.digest(missing), integrity.EXPECTED[restored[0]])

            missing.write_text("tampered", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "differs from baseline"):
                integrity.check(root, repair=True, quarantine_root=None)
            self.assertEqual(missing.read_text(encoding="utf-8"), "tampered")


if __name__ == "__main__":
    unittest.main()
