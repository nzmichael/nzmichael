"""Validating and normalising the scan target.

WHY VALIDATION MATTERS (a real security lesson):
We pass the target to external programs like nmap. If someone typed
`--script=evil` or `-iL /etc/passwd` as the "target", nmap would treat it as an
OPTION, not a host. That is called "argument injection". We protect against it
in two ways:
  1. We never use a shell (subprocess is called with a list, not a string), so
     characters like ; | & $( ) cannot chain extra commands ("command injection").
  2. We only accept things that look like a hostname, IP address or URL, and we
     reject anything starting with "-".
Treat every input as hostile - even your own. It's a habit that pays off.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

# A hostname is dot-separated labels of letters/digits/hyphens, each 1-63 chars,
# not starting or ending with a hyphen, total length up to 253.
_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
_HOSTNAME_RE = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(\.{_LABEL})*\.?$")


@dataclass
class Target:
    original: str            # what the user typed
    host: str                # just the hostname or IP, e.g. scanme.nmap.org
    scheme: Optional[str]    # "http"/"https" if the user gave a URL, else None
    port: Optional[int]      # explicit port if the user gave one

    @property
    def is_ip(self) -> bool:
        try:
            ipaddress.ip_address(self.host)
            return True
        except ValueError:
            return False

    def url(self, scheme: Optional[str] = None) -> str:
        """Build a URL for web tools (nikto, nuclei, webcheck)."""
        scheme = scheme or self.scheme or "http"
        host = f"[{self.host}]" if ":" in self.host else self.host  # IPv6 needs brackets
        default = 443 if scheme == "https" else 80
        # Only add the port if the user specified one AND the scheme matches what they typed.
        if self.port and self.port != default and (self.scheme in (None, scheme)):
            return f"{scheme}://{host}:{self.port}/"
        return f"{scheme}://{host}/"


def parse_target(raw: str) -> Target:
    """Turn user input into a Target, or raise ValueError with a helpful message."""
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("No target given.")
    if raw.startswith("-"):
        raise ValueError("Targets cannot start with '-' (that would be read as a tool option).")
    if any(ch.isspace() for ch in raw):
        raise ValueError("Targets cannot contain spaces.")
    if "://" not in raw and "/" in raw.rstrip("/"):
        # e.g. 10.0.0.0/24 - deliberately not supported.
        raise ValueError(
            "Network ranges (CIDR like 10.0.0.0/24) and bare paths are not supported. reconkit "
            "scans one host at a time so you never accidentally scan systems outside your "
            "authorization. (To give a web path, use a full URL like https://host/path.)"
        )

    # urlparse only finds the host part if there is a "//", so add one for bare hosts.
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    scheme = parsed.scheme.lower() or None
    if scheme not in (None, "http", "https"):
        raise ValueError(f"Unsupported URL scheme '{scheme}'. Use http:// or https://, or just a hostname.")
    try:
        port = parsed.port  # raises ValueError for e.g. host:99999
    except ValueError:
        raise ValueError("The port number in the target is not valid (must be 1-65535).") from None

    host = parsed.hostname
    if not host:
        raise ValueError(f"Could not find a hostname or IP address in '{raw}'.")

    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not _HOSTNAME_RE.match(host):
            raise ValueError(f"'{host}' is not a valid hostname or IP address.") from None

    return Target(original=raw, host=host.rstrip("."), scheme=scheme, port=port)
