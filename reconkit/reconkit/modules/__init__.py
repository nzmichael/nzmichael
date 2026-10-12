"""Scanner modules. Each one wraps a single tool and exposes:

    NAME    - the module's name
    TOOL    - key into tooling.TOOLS (None for pure-Python modules)
    run(target, outdir, options) -> ModuleResult

and a pure `parse_...` / `explain_...` function that turns raw tool output into
Findings. Keeping parsing separate from running means we can test the parsing
with saved sample output, without needing the tool or a network.
"""
