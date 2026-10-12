# reconkit

A **learning-focused** vulnerability assessment CLI. reconkit doesn't reinvent
security tools: it runs well-known free ones (**nmap, nuclei, nikto,
testssl.sh**), parses their output, and explains every result in plain English:
**what it means, why it matters, and what to do next.**

> ⚠️ **Only scan systems you own or have written permission to test.**
> reconkit asks you to type `yes` before every scan and records it in an audit log.

## What it does

| Command | Wraps | If the tool is missing |
|---|---|---|
| `reconkit nmap <target>` | nmap: open ports and service versions | Pure-Python check of ~25 common ports |
| `reconkit testssl <target>` | testssl.sh: TLS protocols, ciphers, certificate | Pure-Python `webcheck` |
| `reconkit nikto <target>` | nikto: web server misconfigurations | Pure-Python `webcheck` |
| `reconkit nuclei <target>` | nuclei: template-based CVE checks | Pure-Python `webcheck` |
| `reconkit webcheck <target>` | built in: security headers, cookies, HTTPS redirect, TLS + cert | always available |
| `reconkit pyports <target>` | built in: TCP connect check of common ports | always available |
| `reconkit all <target>` | everything above, one authorization prompt | |
| `reconkit glossary [term]` | definitions of ~35 security terms | |
| `reconkit tools` | shows what's installed + exact install commands for your OS | |

Every scan subcommand accepts **`--learn`**, which explains the tool and its
key concepts first. Run `reconkit nmap --learn` with no target to just read the lesson.

## Setup on macOS

```bash
# 1. Homebrew (skip if you have it): https://brew.sh
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 2. Python 3 and the security tools
brew install python nmap nuclei nikto testssl

# 3. reconkit itself, in a virtual environment (keeps its packages separate from the system)
cd reconkit
python3 -m venv .venv
source .venv/bin/activate          # run this again in each new terminal
pip install -e ".[dev]"            # -e = "editable": your code edits take effect immediately

# 4. Check everything is found
reconkit tools
```

Linux/Windows: `reconkit tools` prints the right commands for your OS. Try
`reconkit tools --os debian` to see another OS's commands.

## Your first scan

`scanme.nmap.org` is run by the Nmap project, which **explicitly allows** port
scanning it for practice (gently: a few scans a day).

```bash
reconkit nmap --learn scanme.nmap.org     # read the lesson, confirm, scan
reconkit webcheck scanme.nmap.org         # headers + HTTPS check
reconkit glossary tcp                     # look up a term
```

> scanme's permission covers **port scanning**. For the noisier web scanners
> (nikto, nuclei), practise on a lab you own, e.g. OWASP Juice Shop:
> `docker run -p 3000:3000 bkimminich/juice-shop` then `reconkit nikto http://localhost:3000`.

## Where results go

```
reconkit-results/
├── audit.log                          # who scanned what, when, and whether they confirmed (JSON Lines)
└── scanme.nmap.org/
    └── 20261012-143000/               # one folder per run, so nothing is overwritten
        ├── nmap.xml / nmap.log        # raw tool output + exact command and stderr
        ├── findings.json              # every finding, machine-readable
        ├── report.md                  # summary report (Markdown)
        └── report.html                # same report; open in a browser
```

`reconkit-results/` is in `.gitignore` on purpose: **never commit scan results**.
They describe weaknesses in real systems.

## How the code is organised (read it in this order)

```
reconkit/
├── cli.py            # entry point: argparse subcommands and the scan flow
├── target.py         # input validation (why: argument/command injection)
├── authorization.py  # the "type yes" gate and the audit log
├── tooling.py        # finds installed tools; per-OS install commands
├── findings.py       # the shared Finding data model every module returns
├── knowledge.py      # plain-English explanations of common ports
├── modules/
│   ├── base.py       # runs external tools safely (no shell, timeouts, logs)
│   ├── nmap_scan.py  # XML parsing
│   ├── pyports.py    # TCP connect scan with sockets
│   ├── webcheck.py   # requests + ssl: headers, cookies, TLS, certificate
│   └── nuclei_scan.py, nikto_scan.py, testssl_scan.py
├── lessons.py        # --learn text
├── glossary.py       # glossary terms
├── output.py         # terminal colours and "What this means" printing
└── report.py         # Markdown/HTML/JSON reports (note the HTML escaping!)
```

Every module has a pure `parse_…`/`explain_…` function that turns raw output
into `Finding`s. That's what `tests/` exercises, using sample tool output, so the
tests run without network access or any tools installed:

```bash
python -m pytest
```

## Ideas for extending it (good learning exercises)

- Add a port to `knowledge.py` (e.g. 5985 WinRM, 161 SNMP).
- Add a nikto rule to `RULES` in `modules/nikto_scan.py`.
- Flag CVEs that appear in [CISA's KEV catalogue](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
- Add a `diff` command comparing two `findings.json` files ("did my fix work?").

## Disclaimer

For education and **authorized** testing only. Automated scanners miss things
and produce false positives: treat every finding as a lead to verify.
