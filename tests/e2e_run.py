#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""端到端跑一次 scripts/16_full_auto.py（构建/审计用，不属于产品功能）。

用法：
    python tools/e2e_run.py <目标> <标签> [stage]
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from rf.engine.script_runtime import ScriptRun      # noqa: E402


def main() -> int:
    if len(sys.argv) < 3:
        print("用法：e2e_run.py <目标> <标签> [stage]")
        return 2
    target, tag = sys.argv[1], sys.argv[2]
    stage = sys.argv[3] if len(sys.argv) > 3 else "all"
    wd = ROOT / "_e2e" / tag
    params = {"target": target, "stage": stage, "to_desktop": False,
              "run_verify": False, "ids": "", "min_conf": 0}
    run = ScriptRun(ROOT / "scripts" / "16_full_auto.py", params, workdir=wd)
    t0 = time.time()
    run.start()
    if run._thread:
        run._thread.join()
    res = run.result or {}
    print("=" * 60)
    print(f"ok={res.get('ok')} dur={res.get('dur', time.time() - t0):.1f}s")
    if res.get("error"):
        print("ERR:", str(res["error"])[:1200])
    print("-" * 60)
    print(res.get("output", "")[-4000:])
    print("=" * 60)
    print("workdir:", wd)
    return 0 if res.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
