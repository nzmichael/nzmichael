"""The command-line interface: `reconkit <subcommand> [options] <target>`.

We use argparse (built into Python) so there's nothing extra to install.
Each subcommand maps to a function. The scan flow is the same for every module:

    validate target -> check tools -> (--learn lesson) -> AUTHORIZATION
    -> run modules -> explain findings -> write reports -> audit log
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from reconkit import __version__, output, tooling
from reconkit.authorization import confirm_authorization, write_audit
from reconkit.findings import ModuleResult
from reconkit.glossary import GLOSSARY
from reconkit.lessons import LESSONS
from reconkit.modules import nikto_scan, nmap_scan, nuclei_scan, pyports, testssl_scan, webcheck
from reconkit.report import write_reports
from reconkit.target import parse_target

# Registry: subcommand name -> module. Adding a new tool = write a module + one line here.
MODULES = {
    "nmap": nmap_scan,
    "nuclei": nuclei_scan,
    "nikto": nikto_scan,
    "testssl": testssl_scan,
    "webcheck": webcheck,
    "pyports": pyports,
}

# If a tool is missing, run this pure-Python module instead.
FALLBACKS = {"nmap": "pyports", "nuclei": "webcheck", "nikto": "webcheck", "testssl": "webcheck"}

# The order `reconkit all` runs things in: discovery first, then deeper checks.
ALL_ORDER = ["nmap", "webcheck", "testssl", "nikto", "nuclei"]

DESCRIPTIONS = {
    "nmap": "Port & service discovery with nmap (fallback: Python port check)",
    "nuclei": "Template-based vulnerability scan with nuclei (fallback: webcheck)",
    "nikto": "Web server misconfiguration scan with nikto (fallback: webcheck)",
    "testssl": "TLS/SSL configuration check with testssl.sh (fallback: webcheck)",
    "webcheck": "Pure-Python HTTP security header + TLS check (no tools needed)",
    "pyports": "Pure-Python check of ~25 common TCP ports (no tools needed)",
    "all": "Run every module in sequence with one authorization prompt",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reconkit",
        description="A learning-focused wrapper around free security tools. "
                    "Only scan systems you own or are authorized to test.",
        epilog="Start here:  reconkit tools   then   reconkit nmap --learn scanme.nmap.org",
    )
    parser.add_argument("--version", action="version", version=f"reconkit {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    # A "parent" parser holds options shared by every scan subcommand,
    # so we define them once instead of six times.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("target", nargs="?",
                        help="hostname, IP address or URL (e.g. scanme.nmap.org). "
                             "Optional with --learn, to just read the lesson.")
    common.add_argument("--learn", action="store_true",
                        help="explain what this tool does and what to look for before running")
    common.add_argument("-o", "--output-dir", default="reconkit-results", type=Path,
                        help="where results and the audit log go (default: ./reconkit-results)")
    common.add_argument("--timeout", type=int, default=1800,
                        help="max seconds per tool before it's stopped (default: 1800)")

    for name in [*MODULES, "all"]:
        p = sub.add_parser(name, parents=[common], help=DESCRIPTIONS[name], description=DESCRIPTIONS[name])
        if name in ("nmap", "all"):
            p.add_argument("--ports", default="", help="nmap ports, e.g. 22,80,443 or 1-1024")
            p.add_argument("--fast", action="store_true", help="nmap: scan only the top 100 ports")
        if name in ("nuclei", "all"):
            p.add_argument("--severity", default="",
                           help="nuclei: only these severities, e.g. critical,high")
        p.set_defaults(func=cmd_scan, modules=ALL_ORDER if name == "all" else [name])

    g = sub.add_parser("glossary", help="Define common security terms")
    g.add_argument("term", nargs="?", help="search for a term (e.g. 'cve')")
    g.set_defaults(func=cmd_glossary)

    t = sub.add_parser("tools", help="Show which external tools are installed and how to install the rest")
    t.add_argument("--os", choices=["macos", "debian", "fedora", "windows"],
                   help="show install commands for a different OS")
    t.set_defaults(func=cmd_tools)
    return parser


# ---------------------------------------------------------------------------

def plan_modules(requested: list[str]) -> tuple[list[str], list[ModuleResult]]:
    """Decide what will actually run, swapping in fallbacks for missing tools."""
    plan: list[str] = []
    skipped: list[ModuleResult] = []
    for name in requested:
        mod = MODULES[name]
        if mod.TOOL and not tooling.find_tool(mod.TOOL):
            fallback = FALLBACKS.get(name)
            output.warn(f"{tooling.TOOLS[mod.TOOL].name} is not installed - skipping the {name} module.")
            print("  " + tooling.install_hint(mod.TOOL))
            note = f"{tooling.TOOLS[mod.TOOL].name} not installed"
            if fallback:
                note += f"; ran the pure-Python '{fallback}' module instead"
                output.info(f"Using the pure-Python '{fallback}' module as a fallback.")
            skipped.append(ModuleResult(name, ran=False, note=note))
            if fallback and fallback not in plan:
                plan.append(fallback)
        elif name not in plan:
            plan.append(name)
    return plan, skipped


def cmd_scan(args: argparse.Namespace) -> int:
    requested: list[str] = args.modules

    if args.learn:
        for name in requested:
            output.heading(f"Lesson: {name}")
            print(LESSONS[name].strip())
        if not args.target:
            return 0
        print()

    if not args.target:
        output.error("Please give a target, e.g.  reconkit nmap scanme.nmap.org")
        return 2
    try:
        target = parse_target(args.target)
    except ValueError as exc:
        output.error(f"Invalid target: {exc}")
        return 2

    plan, skipped = plan_modules(requested)
    if args.learn:
        for name in plan:
            if name not in requested:
                output.heading(f"Lesson: {name} (fallback)")
                print(LESSONS[name].strip())

    audit_dir: Path = args.output_dir
    if not confirm_authorization(target, plan, audit_dir):
        return 1

    outdir = output.make_results_dir(args.output_dir, target.host)
    output.info(f"Saving results to {outdir}")
    started = datetime.now()
    results: list[ModuleResult] = list(skipped)

    for name in plan:
        output.heading(f"Running module: {name}")
        try:
            result = MODULES[name].run(target, outdir, args)
        except KeyboardInterrupt:
            # Ctrl+C stops the remaining modules, but we still save what we have.
            output.warn("Interrupted - skipping remaining modules and writing the report.")
            results.append(ModuleResult(name, ran=False, note="Interrupted by user (Ctrl+C)."))
            break
        except Exception as exc:  # one broken module must not lose the others' results
            output.error(f"The {name} module failed unexpectedly: {exc!r}")
            result = ModuleResult(name, ran=False, note=f"Unexpected error: {exc!r}")
        results.append(result)
        output.print_module_result(result)
        if not result.ran and name in FALLBACKS and FALLBACKS[name] not in plan:
            # The tool exists but failed (e.g. crashed) - still try the fallback.
            fb = FALLBACKS[name]
            output.info(f"Running the '{fb}' fallback instead.")
            plan.append(fb)

    finished = datetime.now()
    paths = write_reports(outdir, target, results, started, finished)
    write_audit(audit_dir, {"event": "scan_completed", "target": target.host,
                            "modules_run": [r.module for r in results if r.ran],
                            "results_dir": str(outdir)})
    output.heading("Done")
    output.info(f"Markdown report: {paths['markdown']}")
    output.info(f"HTML report:     {paths['html']}  (open it in your browser)")
    output.info(f"Raw tool output and logs are in {outdir}")
    return 0


def cmd_glossary(args: argparse.Namespace) -> int:
    items = sorted(GLOSSARY.items(), key=lambda kv: kv[0].lower())
    if args.term:
        q = args.term.lower()
        items = [(k, v) for k, v in items if q in k.lower() or q in v.lower()]
        if not items:
            output.warn(f"No glossary entry mentions '{args.term}'.")
            return 1
    output.heading("reconkit glossary")
    for term, definition in items:
        print(output.color(term, "bold"))
        print(output.wrap(definition))
        print()
    return 0


def cmd_tools(args: argparse.Namespace) -> int:
    os_key = args.os or tooling.detect_os()
    output.heading(f"External tools (install commands for: {os_key})")
    for key, tool in tooling.TOOLS.items():
        path = tooling.find_tool(key)
        if path:
            print(output.color("  [installed] ", "green") + f"{tool.name:<11} {path}")
        else:
            print(output.color("  [missing]   ", "yellow") + tool.name)
            print("    " + tooling.install_hint(key, os_key).replace("\n", "\n    "))
    print()
    output.info("webcheck and pyports are built in and always available.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print()
        output.warn("Cancelled.")
        return 130  # the conventional exit code for "stopped by Ctrl+C"
    except BrokenPipeError:
        # Happens when output is piped into something like `head` that exits early.
        return 0


if __name__ == "__main__":
    sys.exit(main())
