#!/usr/bin/env python3
"""Sequential, bounded Raw Gadget USB profile fuzz campaign runner.

Runs on the Raspberry Pi only. Each profile is attached for a bounded dwell
period, then SIGINT is sent so Raw Gadget can detach and flush its trace.
The Windows host is expected to run Wireshark/USBPcap separately.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FUZZ_SCRIPT = ROOT / "scripts" / "usb-fuzz.py"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_fuzzer():
    spec = importlib.util.spec_from_file_location("usb_fuzz_module", FUZZ_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load mutator: {FUZZ_SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def find_usb_connect() -> Path:
    candidates = [
        ROOT / "build" / "usb-connect",
        ROOT / "build" / "Release" / "usb-connect",
        ROOT / "build" / "Debug" / "usb-connect",
    ]
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    found = shutil.which("usb-connect")
    if found:
        return Path(found)
    raise RuntimeError(
        "не найден usb-connect. Сначала выполните: "
        "sudo python3 scripts/usb-lab.py build"
    )


def capture_snapshot(directory: Path | None) -> dict[str, dict[str, Any]]:
    snapshot: dict[str, dict[str, Any]] = {}
    if directory is None or not directory.is_dir():
        return snapshot
    for path in sorted(directory.iterdir()):
        if path.is_file() and path.suffix.lower() in (".pcap", ".pcapng"):
            try:
                st = path.stat()
                snapshot[str(path.resolve())] = {
                    "size_bytes": st.st_size,
                    "mtime_ns": st.st_mtime_ns,
                }
            except OSError:
                continue
    return snapshot


def capture_delta(before: dict[str, dict[str, Any]],
                  after: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    changed = []
    for path, current in after.items():
        previous = before.get(path)
        if previous != current:
            changed.append({
                "path": path,
                "size_before": previous["size_bytes"] if previous else None,
                "size_after": current["size_bytes"],
                "mtime_ns": current["mtime_ns"],
                "new_file": previous is None,
            })
    return changed


def append_jsonl(path: Path, row: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def terminate_process(proc: subprocess.Popen[str], grace: float) -> tuple[str, int | None]:
    """Ask usb-connect to detach cleanly; escalate only if it ignores SIGINT."""
    if proc.poll() is not None:
        return "already_exited", proc.returncode
    try:
        proc.send_signal(signal.SIGINT)
    except ProcessLookupError:
        return "already_exited", proc.poll()
    try:
        return "sigint", proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            return "sigterm", proc.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            proc.kill()
            return "sigkill", proc.wait(timeout=grace)


def run_case(binary: Path, profile: Path, case_no: int, args: argparse.Namespace,
             out: Path, capture_dir: Path | None) -> dict[str, Any]:
    trace_dir = out / "traces"
    trace_dir.mkdir(parents=True, exist_ok=True)
    trace_path = trace_dir / f"case-{case_no:05d}.device.jsonl"
    stdout_path = trace_dir / f"case-{case_no:05d}.stdout.log"
    stderr_path = trace_dir / f"case-{case_no:05d}.stderr.log"
    run_id = f"{args.run_id}-case-{case_no:05d}"
    command = [
        str(binary), "run", str(profile),
        "--backend", "raw-gadget",
        "--udc-driver", args.udc_driver,
        "--udc-device", args.udc_device,
        "--speed", args.speed,
        "--trace", str(trace_path),
        "--run-id", run_id,
    ]
    if args.allow_research:
        command.append("--allow-research")

    row: dict[str, Any] = {
        "case": case_no,
        "profile": str(profile.resolve()),
        "profile_sha256": sha256(profile),
        "run_id": run_id,
        "command": command,
        "started_at": utc_now(),
        "status": "STARTING",
        "dwell_seconds_requested": args.dwell_seconds,
        "trace": str(trace_path),
        "stdout_log": str(stdout_path),
        "stderr_log": str(stderr_path),
    }
    before_capture = capture_snapshot(capture_dir)
    start = time.monotonic()

    with stdout_path.open("w", encoding="utf-8") as stdout, \
         stderr_path.open("w", encoding="utf-8") as stderr:
        try:
            proc = subprocess.Popen(
                command,
                cwd=str(ROOT),
                stdout=stdout,
                stderr=stderr,
                text=True,
                start_new_session=True,
            )
        except OSError as exc:
            row.update(status="LAUNCH_ERROR", error=str(exc))
            row["ended_at"] = utc_now()
            row["duration_seconds"] = round(time.monotonic() - start, 3)
            row["capture_files_changed"] = capture_delta(before_capture, capture_snapshot(capture_dir))
            return row

        row["pid"] = proc.pid
        # Wait briefly to distinguish a failed validation/backend startup from a live device.
        startup_deadline = time.monotonic() + args.startup_grace
        try:
            while proc.poll() is None and time.monotonic() < startup_deadline:
                time.sleep(min(0.1, max(0.0, startup_deadline - time.monotonic())))
        except KeyboardInterrupt:
            row["interrupted_by_user"] = True
            stop_method, returncode = terminate_process(proc, args.stop_grace)
            row.update(status="INTERRUPTED", stop_method=stop_method, returncode=returncode)

        if row.get("status") == "INTERRUPTED":
            pass
        elif proc.poll() is not None:
            row.update(status="START_FAILED", returncode=proc.returncode)
        else:
            row["status"] = "RUNNING"
            row["device_started_at"] = utc_now()
            deadline = time.monotonic() + args.dwell_seconds
            try:
                while proc.poll() is None and time.monotonic() < deadline:
                    time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))
            except KeyboardInterrupt:
                row["interrupted_by_user"] = True
            if proc.poll() is None:
                stop_method, returncode = terminate_process(proc, args.stop_grace)
                row["stop_method"] = stop_method
                row["returncode"] = returncode
                row["status"] = "INTERRUPTED" if row.get("interrupted_by_user") else ("COMPLETED" if returncode == 0 else "STOP_ERROR")
            else:
                row.update(status="DEVICE_EXITED_EARLY", returncode=proc.returncode)

    row["ended_at"] = utc_now()
    row["duration_seconds"] = round(time.monotonic() - start, 3)
    row["trace_exists"] = trace_path.exists()
    row["trace_bytes"] = trace_path.stat().st_size if trace_path.exists() else 0
    row["capture_files_changed"] = capture_delta(before_capture, capture_snapshot(capture_dir))
    if stderr_path.exists():
        try:
            row["stderr_tail"] = stderr_path.read_text(encoding="utf-8", errors="replace")[-4000:]
        except OSError:
            pass
    return row


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Последовательная кампания USB profile fuzzing для Raw Gadget на Raspberry Pi"
    )
    parser.add_argument("--base", required=True, help="базовый JSON-профиль")
    parser.add_argument("--count", type=int, default=5, help="число вариантов (1..1000)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--mutations", type=int, default=1)
    parser.add_argument("--out-dir", default="runs/fuzz/auto-campaign")
    parser.add_argument("--udc-driver", required=True)
    parser.add_argument("--udc-device", required=True)
    parser.add_argument("--speed", choices=("high", "full", "low"), default="high")
    parser.add_argument("--dwell-seconds", type=float, default=10.0,
                        help="сколько держать каждый профиль подключённым")
    parser.add_argument("--startup-grace", type=float, default=2.0,
                        help="сколько ждать, чтобы определить ошибку старта")
    parser.add_argument("--stop-grace", type=float, default=5.0,
                        help="тайм-аут чистой остановки после SIGINT")
    parser.add_argument("--settle-seconds", type=float, default=2.0,
                        help="пауза между случаями для USB/host стабилизации")
    parser.add_argument("--capture-dir", help="необязательно: каталог PCAPNG на Pi/SMB-шаре")
    parser.add_argument("--run-id", default="usb-fuzz")
    parser.add_argument("--allow-research", action="store_true",
                        help="разрешить профили validation.mode=research")
    parser.add_argument("--continue-on-error", action="store_true",
                        help="продолжать после ошибки старта/раннего завершения")
    parser.add_argument("--confirm-lab", action="store_true",
                        help="подтвердить, что подключён только собственный изолированный тестовый хост")
    parser.add_argument("--dry-run", action="store_true",
                        help="создать профили и план без запуска USB Gadget")
    args = parser.parse_args()

    if not args.confirm_lab and not args.dry_run:
        parser.error("для реального запуска обязателен --confirm-lab")
    if not args.allow_research and not args.dry_run:
        parser.error("мутации помечены validation.mode=research; для запуска добавьте --allow-research только в изолированной лаборатории")
    if args.count < 1 or args.count > 1000:
        parser.error("--count должен быть в диапазоне 1..1000")
    if args.dwell_seconds <= 0 or args.dwell_seconds > 600:
        parser.error("--dwell-seconds должен быть в диапазоне (0, 600]")
    if not 0 <= args.startup_grace <= 30 or not 0.1 <= args.stop_grace <= 30:
        parser.error("недопустимое значение startup/stop grace")
    if not 0 <= args.settle_seconds <= 60:
        parser.error("--settle-seconds должен быть в диапазоне 0..60")
    if args.mutations < 1 or args.mutations > 100:
        parser.error("--mutations должен быть в диапазоне 1..100")
    if not platform.system().lower() == "linux":
        parser.error("реальная кампания запускается только на Raspberry Pi/Linux")
    if not args.dry_run:
        if os.geteuid() != 0:
            parser.error("запустите через sudo: Raw Gadget требует root-доступа")
        if not Path("/dev/raw-gadget").exists():
            parser.error("/dev/raw-gadget не найден; проверьте ядро/модуль Raw Gadget")
        if not Path("/sys/class/udc").exists() or not any(Path("/sys/class/udc").glob("*")):
            parser.error("UDC не обнаружен в /sys/class/udc")

    base = Path(args.base).resolve()
    if not base.is_file():
        parser.error(f"базовый профиль не найден: {base}")
    out = Path(args.out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    capture_dir = Path(args.capture_dir).resolve() if args.capture_dir else None
    if capture_dir is not None and not capture_dir.is_dir():
        parser.error(f"--capture-dir не существует или не каталог: {capture_dir}")

    fuzzer = load_fuzzer()
    cases = fuzzer.generate(base, args.count, args.seed, out, args.mutations)
    campaign_log = out / "campaign.jsonl"
    summary_path = out / "summary.json"
    campaign_log.write_text("", encoding="utf-8")
    (out / "runner-config.json").write_text(json.dumps({
        "base": str(base),
        "base_sha256": sha256(base),
        "seed": args.seed,
        "count": args.count,
        "mutations_per_case": args.mutations,
        "dwell_seconds": args.dwell_seconds,
        "udc_driver": args.udc_driver,
        "udc_device": args.udc_device,
        "speed": args.speed,
        "run_id": args.run_id,
        "capture_dir": str(capture_dir) if capture_dir else None,
        "dry_run": args.dry_run,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if args.dry_run:
        plan = []
        for case in cases:
            plan.append({
                "case": case["case"],
                "profile": case["profile"],
                "sha256": case["sha256"],
                "status": "DRY_RUN_ONLY",
            })
        (out / "campaign.jsonl").write_text(
            "".join(json.dumps(x, ensure_ascii=False) + "\n" for x in plan),
            encoding="utf-8",
        )
        (out / "summary.json").write_text(json.dumps({
            "status": "DRY_RUN_ONLY", "generated": len(cases), "executed": 0,
            "results": plan,
        }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"Dry run: сгенерировано {len(cases)} профилей; USB Gadget не запускался.")
        print(f"План: {campaign_log}")
        return 0

    binary = find_usb_connect()
    results: list[dict[str, Any]] = []
    interrupted = False
    for index, case in enumerate(cases, start=1):
        profile = Path(case["profile"])
        print(f"[{index}/{len(cases)}] case-{index:05d}: запуск {profile.name}", flush=True)
        row = run_case(binary, profile, index, args, out, capture_dir)
        results.append(row)
        append_jsonl(campaign_log, row)
        print(f"  -> {row['status']} ({row.get('duration_seconds', 0)} s)", flush=True)
        if row["status"] == "INTERRUPTED":
            interrupted = True
            break
        if row["status"] in ("LAUNCH_ERROR", "START_FAILED", "DEVICE_EXITED_EARLY", "STOP_ERROR") and not args.continue_on_error:
            print("Остановка: ошибка запуска/раннее завершение. Подробности в traces/*.stderr.log", file=sys.stderr)
            break
        if index < len(cases) and args.settle_seconds:
            try:
                time.sleep(args.settle_seconds)
            except KeyboardInterrupt:
                interrupted = True
                break

    summary = {
        "status": "INTERRUPTED" if interrupted else "COMPLETED",
        "seed": args.seed,
        "generated": len(cases),
        "executed": len(results),
        "completed": sum(x["status"] == "COMPLETED" for x in results),
        "startup_errors": sum(x["status"] in ("LAUNCH_ERROR", "START_FAILED", "DEVICE_EXITED_EARLY", "STOP_ERROR") for x in results),
        "interrupted_cases": sum(x["status"] == "INTERRUPTED" for x in results),
        "results": results,
        "note": "USB capture changes are correlated by timestamp/file size only. PCAPNG symptoms are not proof of a Windows crash.",
    }
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Итог: {summary_path}")
    return 130 if interrupted else (1 if summary["startup_errors"] else 0)


if __name__ == "__main__":
    raise SystemExit(main())
