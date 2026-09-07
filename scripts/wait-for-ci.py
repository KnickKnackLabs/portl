#!/usr/bin/env python3
"""Require a successful CI workflow for the exact commit being released."""

import json
import os
import subprocess
import time


def wait_for_ci(repo, sha):
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        payload = json.loads(subprocess.check_output([
            "gh", "api", "--method", "GET",
            f"repos/{repo}/actions/workflows/ci.yml/runs",
            "-f", f"head_sha={sha}", "-f", "per_page=100",
        ], text=True))
        runs = [
            run for run in payload["workflow_runs"]
            if run["head_sha"] == sha
            and run["event"] in {"push", "workflow_dispatch"}
        ]
        if runs:
            # Never release on an older success while a newer attempt is failing.
            run = max(runs, key=lambda run: run["id"])
            print(f"Waiting for CI run {run['id']} at {sha}", flush=True)
            subprocess.run([
                "gh", "run", "watch", str(run["id"]), "--repo", repo,
                "--exit-status", "--interval", "15",
            ], check=True)
            return
        print(f"Waiting for CI to start at {sha}", flush=True)
        time.sleep(15)
    raise TimeoutError(f"No push or manual CI run found for {sha} within 10 minutes")


if __name__ == "__main__":
    wait_for_ci(os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_SHA"])
