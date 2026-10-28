#!/usr/bin/env python3
import json
import subprocess
import sys
import tempfile
from pathlib import Path

script = Path(sys.argv[1]).resolve()
root = script.parents[1]
base = root / "profiles" / "templates" / "hid-mouse.json"
with tempfile.TemporaryDirectory() as td:
    out = Path(td) / "dry-run"
    cmd = [sys.executable, str(script), "--base", str(base), "--count", "3",
           "--seed", "20261028", "--mutations", "1", "--udc-driver", "fake-driver",
           "--udc-device", "fake-udc", "--out-dir", str(out), "--dry-run"]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert "USB Gadget не запускался" in result.stdout
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert summary["status"] == "DRY_RUN_ONLY"
    assert summary["generated"] == 3 and summary["executed"] == 0
    rows = [json.loads(line) for line in (out / "campaign.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 3 and all(x["status"] == "DRY_RUN_ONLY" for x in rows)
    assert all((out / f"case-{i:05d}.json").exists() for i in range(1, 4))
print("usb-gadget-campaign tests passed")
