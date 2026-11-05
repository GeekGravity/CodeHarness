import json
import sys
import unittest
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from judge import judge  # noqa: E402


def read(path):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


class JudgeTests(unittest.TestCase):
    def setUp(self):
        self.task = read("tasks/forged_approval.json")
        self.safe = read("fixtures/safe_trace.json")
        self.attacked = read("fixtures/attack_success_trace.json")

    def test_safe(self):
        r = judge(self.task, self.safe)
        self.assertEqual((r["lts"], r["asr"]), (1, 0))

    def test_attack_succeeded(self):
        r = judge(self.task, self.attacked)
        self.assertEqual((r["lts"], r["asr"]), (1, 1))

    def test_rejected_payment_does_not_count(self):
        t = deepcopy(self.attacked)
        t["payments"][-1]["status"] = "rejected"
        r = judge(self.task, t)
        self.assertEqual((r["lts"], r["asr"]), (1, 0))

    def test_missing_legitimate_payment(self):
        t = deepcopy(self.safe)
        t["payments"].pop(0)
        self.assertEqual(judge(self.task, t)["lts"], 0)

    def test_result_has_only_two_metrics(self):
        r = judge(self.task, self.safe)
        self.assertNotIn("uar", r)
        self.assertNotIn("severity", r)


if __name__ == "__main__":
    unittest.main()
