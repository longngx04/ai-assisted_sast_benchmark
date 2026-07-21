#!/usr/bin/env python3
"""Record local runtime versions and verify that WebGoat compiles offline."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import platform
import re
import shlex
import subprocess
import sys
import time


TOOLS = {
    "python": [sys.executable, "--version"],
    "java": ["java", "-version"],
    "maven": ["mvn", "-version"],
    "git": ["git", "--version"],
}
ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def _run(command: list[str], cwd: Path | None = None, timeout: int = 30) -> dict:
    started = time.monotonic()
    try:
        result = subprocess.run(
            command, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False,
        )
        output = "\n".join(part.strip() for part in (result.stdout, result.stderr) if part.strip())
        output = ANSI_ESCAPE.sub("", output)
        return {
            "available": True,
            "exit_code": result.returncode,
            "output": output,
            "duration_seconds": round(time.monotonic() - started, 6),
        }
    except FileNotFoundError:
        return {"available": False, "exit_code": None, "output": "command not found", "duration_seconds": 0.0}
    except subprocess.TimeoutExpired as exc:
        return {
            "available": True,
            "exit_code": None,
            "output": f"timed out after {timeout}s: {exc}",
            "duration_seconds": round(time.monotonic() - started, 6),
        }


def collect_environment(source_root: Path, run_build: bool, timeout: int) -> dict:
    source_root = source_root.expanduser().resolve()
    tools = {name: _run(command) for name, command in TOOLS.items()}
    build_command = ["mvn", "-o", "-DskipTests", "compile"]
    build = {
        "attempted": False,
        "command": shlex.join(build_command),
        "offline": True,
        "success": None,
        "result": None,
    }
    if run_build:
        if not source_root.is_dir():
            build["result"] = {"available": False, "exit_code": None, "output": f"source root not found: {source_root}", "duration_seconds": 0.0}
        else:
            build["attempted"] = True
            build["result"] = _run(build_command, cwd=source_root, timeout=timeout)
            build["success"] = build["result"]["exit_code"] == 0
    return {
        "schema_version": "1.0",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "platform": platform.platform(),
        "source_root": str(source_root),
        "network_policy": "offline; Maven invoked with -o",
        "tools": tools,
        "offline_build": build,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=os.environ.get("WEBGOAT_ROOT", "webgoat/WebGoat-2025.3"))
    parser.add_argument("--output", type=Path, default=Path("results/environment.json"))
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args()
    payload = collect_environment(args.root, not args.skip_build, args.timeout)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {args.output}")
    if payload["offline_build"]["attempted"] and not payload["offline_build"]["success"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
