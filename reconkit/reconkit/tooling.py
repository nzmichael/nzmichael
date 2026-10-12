"""Detecting which external tools are installed, and how to install the rest.

`shutil.which("nmap")` searches the folders in your PATH environment variable,
exactly like your shell does when you type a command. If it returns None, the
tool isn't installed (or isn't on your PATH).
"""

from __future__ import annotations

import platform
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class ToolInfo:
    name: str
    binaries: list[str]                 # possible command names, first match wins
    homepage: str
    install: dict[str, str] = field(default_factory=dict)  # OS key -> command
    notes: str = ""


TOOLS: dict[str, ToolInfo] = {
    "nmap": ToolInfo(
        name="nmap",
        binaries=["nmap"],
        homepage="https://nmap.org",
        install={
            "macos": "brew install nmap",
            "debian": "sudo apt update && sudo apt install -y nmap",
            "fedora": "sudo dnf install -y nmap",
            "windows": "winget install -e --id Insecure.Nmap   (or the installer at https://nmap.org/download.html)",
        },
    ),
    "nuclei": ToolInfo(
        name="nuclei",
        binaries=["nuclei"],
        homepage="https://github.com/projectdiscovery/nuclei",
        install={
            "macos": "brew install nuclei",
            "debian": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest   "
                      "(needs Go: sudo apt install -y golang-go; then add ~/go/bin to PATH. On Kali: sudo apt install -y nuclei)",
            "fedora": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest   (needs Go: sudo dnf install -y golang)",
            "windows": "Download the Windows zip from https://github.com/projectdiscovery/nuclei/releases (or use WSL)",
        },
        notes="The first run downloads nuclei's template library (a few hundred MB); that's normal.",
    ),
    "nikto": ToolInfo(
        name="nikto",
        binaries=["nikto", "nikto.pl"],
        homepage="https://github.com/sullo/nikto",
        install={
            "macos": "brew install nikto",
            "debian": "sudo apt install -y nikto   (or: git clone https://github.com/sullo/nikto && put nikto/program on your PATH)",
            "fedora": "sudo dnf install -y nikto",
            "windows": "Use WSL (Ubuntu) and run: sudo apt install -y nikto",
        },
    ),
    "testssl": ToolInfo(
        name="testssl.sh",
        # Homebrew and Debian install it as `testssl`; a git clone gives `testssl.sh`.
        binaries=["testssl.sh", "testssl"],
        homepage="https://testssl.sh",
        install={
            "macos": "brew install testssl",
            "debian": "sudo apt install -y testssl.sh",
            "fedora": "sudo dnf install -y testssl",
            "windows": "Use WSL (Ubuntu) and run: sudo apt install -y testssl.sh",
        },
    ),
}


def detect_os() -> str:
    """Return 'macos', 'debian', 'fedora', 'windows' or 'linux'."""
    system = platform.system()
    if system == "Darwin":          # macOS reports itself as "Darwin" (its kernel's name)
        return "macos"
    if system == "Windows":
        return "windows"
    if system == "Linux":
        os_release = Path("/etc/os-release")
        text = os_release.read_text(errors="ignore").lower() if os_release.exists() else ""
        if any(w in text for w in ("debian", "ubuntu", "kali", "mint", "pop")):
            return "debian"
        if any(w in text for w in ("fedora", "rhel", "centos", "rocky", "alma")):
            return "fedora"
        return "linux"
    return "linux"


def find_tool(key: str) -> Optional[str]:
    """Full path to the tool's executable, or None if it isn't installed."""
    for binary in TOOLS[key].binaries:
        path = shutil.which(binary)
        if path:
            return path
    return None


def install_hint(key: str, os_key: Optional[str] = None) -> str:
    tool = TOOLS[key]
    os_key = os_key or detect_os()
    cmd = tool.install.get(os_key) or tool.install.get("debian") or ""
    hint = f"Install {tool.name} with:\n    {cmd}\n  Project page: {tool.homepage}"
    if os_key == "macos" and not shutil.which("brew"):
        hint += "\n  (You need Homebrew first: see https://brew.sh)"
    if tool.notes:
        hint += f"\n  Note: {tool.notes}"
    return hint
