"""Release-gate regressions; no GitHub connection or real waiting required."""

import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "wait_for_ci", Path(__file__).resolve().parents[1] / "wait-for-ci.py"
)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def runs(*entries):
    return json.dumps({"workflow_runs": [
        {"id": identifier, "head_sha": sha, "event": event}
        for identifier, sha, event in entries
    ]})


class ReleaseGateTests(unittest.TestCase):
    def test_only_watches_the_latest_eligible_run_for_the_exact_commit(self):
        payload = runs(
            (10, "release-sha", "push"),
            (30, "different-sha", "push"),
            (40, "release-sha", "pull_request"),
            (20, "release-sha", "workflow_dispatch"),
        )
        with patch.object(gate.subprocess, "check_output", return_value=payload) as api:
            with patch.object(gate.subprocess, "run") as watch:
                gate.wait_for_ci("org/repo", "release-sha")
        self.assertIn("repos/org/repo/actions/workflows/ci.yml/runs", api.call_args.args[0])
        self.assertIn("head_sha=release-sha", api.call_args.args[0])
        watch.assert_called_once_with([
            "gh", "run", "watch", "20", "--repo", "org/repo",
            "--exit-status", "--interval", "15",
        ], check=True)

    def test_failed_ci_stops_release(self):
        with patch.object(gate.subprocess, "check_output", return_value=runs(
            (10, "release-sha", "push"), (20, "release-sha", "push")
        )):
            with patch.object(gate.subprocess, "run", side_effect=subprocess.CalledProcessError(
                1, "gh run watch"
            )) as watch:
                with self.assertRaises(subprocess.CalledProcessError):
                    gate.wait_for_ci("org/repo", "release-sha")
        self.assertEqual(watch.call_count, 1)

    def test_waits_for_ci_to_appear(self):
        with patch.object(gate.subprocess, "check_output", side_effect=[
            runs(), runs((10, "release-sha", "push"))
        ]):
            with patch.object(gate.time, "sleep") as sleep:
                with patch.object(gate.subprocess, "run") as watch:
                    gate.wait_for_ci("org/repo", "release-sha")
        sleep.assert_called_once_with(15)
        watch.assert_called_once()

    def test_missing_ci_times_out_without_releasing(self):
        with patch.object(gate.subprocess, "check_output", return_value=runs()):
            with patch.object(gate.time, "monotonic", side_effect=[0, 0, 601]):
                with patch.object(gate.time, "sleep"):
                    with patch.object(gate.subprocess, "run") as watch:
                        with self.assertRaises(TimeoutError):
                            gate.wait_for_ci("org/repo", "release-sha")
        watch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
