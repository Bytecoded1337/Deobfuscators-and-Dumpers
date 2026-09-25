from __future__ import annotations

import subprocess
from pathlib import Path


def run_external_decompiler(bytecode: Path, executable: Path, extra_args: list[str] | None = None) -> str:
    """Run a user-selected open-source decompiler on already reconstructed standard bytecode."""
    cmd = [str(executable)]
    cmd.extend(extra_args or [])
    cmd.append(str(bytecode))
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace")
    if proc.returncode != 0:
        raise RuntimeError(f"external decompiler failed ({proc.returncode}):\n{proc.stderr}")
    if not proc.stdout.strip():
        raise RuntimeError("external decompiler returned empty stdout")
    return proc.stdout
