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
        "recommended_actions": [],
        "snapshot": {"epoch": index, "minted_supply": "4800000.0000"},
    }


class TestStatusHistory(unittest.TestCase):
    def test_append_history_creates_and_reads_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            history_path = Path(tmp_dir) / "NETWORK_HISTORY.jsonl"
            meta = append_history(history_path=history_path, payload=_payload(1), max_entries=10, recent_limit=5)

            self.assertTrue(history_path.exists())
            self.assertEqual(meta["history_total_entries"], 1)
            self.assertTrue(meta["history_appended"])
            self.assertEqual(len(meta["recent_history"]), 1)
            self.assertEqual(meta["recent_history"][0]["epoch"], 1)
            self.assertEqual(meta["recent_history"][0]["recommended_actions"], [])
            self.assertEqual(meta["recent_history"][0]["previous_history_hash"], "")
            self.assertEqual(len(meta["recent_history"][0]["history_hash"]), 64)
            self.assertTrue(meta["history_chain"]["enabled"])
            self.assertTrue(meta["history_chain"]["valid"])

    def test_append_history_trims_to_max_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            history_path = Path(tmp_dir) / "NETWORK_HISTORY.jsonl"
            for idx in range(1, 8):
                meta = append_history(history_path=history_path, payload=_payload(idx), max_entries=3, recent_limit=5)

            self.assertEqual(meta["history_total_entries"], 3)
            self.assertTrue(meta["history_appended"])
            self.assertEqual([item["epoch"] for item in meta["recent_history"]], [5, 6, 7])
            self.assertTrue(meta["history_chain"]["valid"])

            lines = history_path.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), 3)

    def test_append_history_ignores_malformed_lines(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            history_path = Path(tmp_dir) / "NETWORK_HISTORY.jsonl"
            history_path.write_text('{"epoch":1}\nnot-json\n{"epoch":2}\n', encoding="utf-8")
            meta = append_history(history_path=history_path, payload=_payload(3), max_entries=10, recent_limit=5)

            self.assertEqual(meta["history_total_entries"], 3)
            self.assertTrue(meta["history_appended"])
            self.assertEqual(meta["recent_history"][-1]["epoch"], 3)
            parsed = [json.loads(line) for line in history_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertEqual(len(parsed), 3)
            self.assertTrue(meta["history_chain"]["valid"])

    def test_append_history_skips_duplicate_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            history_path = Path(tmp_dir) / "NETWORK_HISTORY.jsonl"
            first = _payload(1)
            second = dict(first)
            second["generated_at_utc"] = "2026-02-24T14:00:59+00:00"

            meta_first = append_history(history_path=history_path, payload=first, max_entries=10, recent_limit=5)
            meta_second = append_history(history_path=history_path, payload=second, max_entries=10, recent_limit=5)

            self.assertTrue(meta_first["history_appended"])
            self.assertFalse(meta_second["history_appended"])
            self.assertEqual(meta_second["history_total_entries"], 1)

    def test_append_history_can_force_duplicate_append(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            history_path = Path(tmp_dir) / "NETWORK_HISTORY.jsonl"
            first = _payload(1)
            second = dict(first)
            second["generated_at_utc"] = "2026-02-24T14:00:59+00:00"

            append_history(history_path=history_path, payload=first, max_entries=10, recent_limit=5)
            meta = append_history(
                history_path=history_path,
                payload=second,
                max_entries=10,
                recent_limit=5,
                skip_if_unchanged=False,
            )

            self.assertTrue(meta["history_appended"])
            self.assertEqual(meta["history_total_entries"], 2)
            self.assertTrue(meta["history_chain"]["valid"])

    def test_append_history_chain_links_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            history_path = Path(tmp_dir) / "NETWORK_HISTORY.jsonl"
            meta_first = append_history(history_path=history_path, payload=_payload(1), max_entries=10, recent_limit=5)
            meta_second = append_history(history_path=history_path, payload=_payload(2), max_entries=10, recent_limit=5)

            first_hash = meta_first["recent_history"][0]["history_hash"]
            second = meta_second["recent_history"][-1]
            self.assertEqual(second["previous_history_hash"], first_hash)
            self.assertEqual(len(second["history_hash"]), 64)
            self.assertTrue(meta_second["history_chain"]["enabled"])
            self.assertTrue(meta_second["history_chain"]["valid"])

    def test_append_history_chain_detects_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            history_path = Path(tmp_dir) / "NETWORK_HISTORY.jsonl"
            append_history(history_path=history_path, payload=_payload(1), max_entries=10, recent_limit=5)
            append_history(history_path=history_path, payload=_payload(2), max_entries=10, recent_limit=5)

            records = [json.loads(line) for line in history_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            records[1]["health_level"] = "DEGRADED"
            history_path.write_text("\n".join(json.dumps(item, ensure_ascii=False) for item in records) + "\n", encoding="utf-8")

            meta = append_history(
                history_path=history_path,
                payload=_payload(3),
                max_entries=10,
                recent_limit=5,
                skip_if_unchanged=False,
            )
            self.assertFalse(meta["history_chain"]["valid"])
            self.assertGreaterEqual(meta["history_chain"]["broken_index"], 0)
            self.assertTrue(meta["history_chain"]["broken_reason"])

    def test_append_history_exposes_trend_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            history_path = Path(tmp_dir) / "NETWORK_HISTORY.jsonl"
            p1 = _payload(1)
            p2 = _payload(2)
            p3 = _payload(3)
            p1["health_level"] = "WARN"
            p2["health_level"] = "OK"
            p3["health_level"] = "DEGRADED"
            p1["avg_winner_latency_ms"] = 50.0
            p2["avg_winner_latency_ms"] = 47.5
            p3["avg_winner_latency_ms"] = 49.0
            p3["status_ok"] = False
            p3["status_reasons"] = ["qa_failed"]
            p3["advisories"] = []

            append_history(history_path=history_path, payload=p1, max_entries=10, trend_window=10)
            append_history(history_path=history_path, payload=p2, max_entries=10, trend_window=10)
            meta = append_history(history_path=history_path, payload=p3, max_entries=10, trend_window=10)

            trend = meta["history_trend"]
            self.assertEqual(trend["sample_size"], 3)
            self.assertEqual(trend["health_counts"]["WARN"], 1)
            self.assertEqual(trend["health_counts"]["OK"], 1)
            self.assertEqual(trend["health_counts"]["DEGRADED"], 1)
            self.assertEqual(trend["latest_health"], "DEGRADED")
            self.assertEqual(trend["previous_health"], "OK")
            self.assertTrue(trend["health_changed"])
            self.assertAlmostEqual(trend["avg_latency_delta_ms"], 1.5)
            self.assertEqual(trend["epoch_delta"], 1)


if __name__ == "__main__":
    unittest.main()
