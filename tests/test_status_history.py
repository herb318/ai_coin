import json
import tempfile
import unittest
from pathlib import Path

from scripts.network_status_agent import append_history


def _payload(index: int) -> dict:
    return {
        "generated_at_utc": f"2026-02-24T14:00:{index:02d}+00:00",
        "health_level": "OK",
        "status_ok": True,
        "production_checks": False,
        "qa_overall_passed": True,
        "network_size_nodes": 5,
        "avg_winner_latency_ms": 45.6,
        "requests_executed": 5,
        "status_reasons": [],
        "advisories": [],
        "snapshot": {"epoch": index, "minted_supply": "4800000.0000"},
    }


class TestStatusHistory(unittest.TestCase):
    def test_append_history_creates_and_reads_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            history_path = Path(tmp_dir) / "NETWORK_HISTORY.jsonl"
            meta = append_history(history_path=history_path, payload=_payload(1), max_entries=10, recent_limit=5)

            self.assertTrue(history_path.exists())
            self.assertEqual(meta["history_total_entries"], 1)
            self.assertEqual(len(meta["recent_history"]), 1)
            self.assertEqual(meta["recent_history"][0]["epoch"], 1)

    def test_append_history_trims_to_max_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            history_path = Path(tmp_dir) / "NETWORK_HISTORY.jsonl"
            for idx in range(1, 8):
                meta = append_history(history_path=history_path, payload=_payload(idx), max_entries=3, recent_limit=5)

            self.assertEqual(meta["history_total_entries"], 3)
            self.assertEqual([item["epoch"] for item in meta["recent_history"]], [5, 6, 7])

            lines = history_path.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), 3)

    def test_append_history_ignores_malformed_lines(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            history_path = Path(tmp_dir) / "NETWORK_HISTORY.jsonl"
            history_path.write_text('{"epoch":1}\nnot-json\n{"epoch":2}\n', encoding="utf-8")
            meta = append_history(history_path=history_path, payload=_payload(3), max_entries=10, recent_limit=5)

            self.assertEqual(meta["history_total_entries"], 3)
            self.assertEqual(meta["recent_history"][-1]["epoch"], 3)
            parsed = [json.loads(line) for line in history_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertEqual(len(parsed), 3)


if __name__ == "__main__":
    unittest.main()
