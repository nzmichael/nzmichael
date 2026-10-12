"""Shared helper for running external tools safely."""

from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path

from reconkit import output


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


def run_command(cmd: list[str], outdir: Path, log_name: str, timeout: int) -> CommandResult:
    """Run a tool and save everything it printed to <outdir>/<log_name>.log.

    SECURITY NOTE: `cmd` is a LIST, e.g. ["nmap", "-sV", "scanme.nmap.org"].
    subprocess passes each item straight to the program as one argument, with no
    shell involved. If we instead built one string and used shell=True, a target
    like "example.com; rm -rf ~" would run the second command. Never use
    shell=True with input that came from a user.
    """
    # shlex.join shows the command exactly as you could paste it into a terminal.
    # Printing it is deliberate: copy it and run it yourself to learn the tool.
    output.info("Running: " + output.color(shlex.join(cmd), "bold"))
    output.info(f"(This can take a while. Timeout: {timeout // 60} min. Press Ctrl+C to abort.)")
    log_path = outdir / f"{log_name}.log"
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,   # collect stdout/stderr instead of printing them
            text=True,             # give us str instead of bytes
            errors="replace",      # never crash on odd characters in tool output
            timeout=timeout,       # never hang forever
        )
        result = CommandResult(proc.returncode, proc.stdout, proc.stderr)
    except subprocess.TimeoutExpired as exc:
        def _s(v):
            return v.decode(errors="replace") if isinstance(v, bytes) else (v or "")
        result = CommandResult(-1, _s(exc.stdout), _s(exc.stderr), timed_out=True)
        output.warn(f"The tool did not finish within {timeout} seconds and was stopped.")
    log_path.write_text(
        f"$ {shlex.join(cmd)}\n# exit code: {result.returncode}\n\n"
        f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}\n",
        encoding="utf-8",
    )
    return result
