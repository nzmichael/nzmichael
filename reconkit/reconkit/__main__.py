# This file lets you run the tool with `python -m reconkit ...` even if you
# have not installed the `reconkit` command. Python runs __main__.py when you
# execute a package with -m.
from reconkit.cli import main

raise SystemExit(main())
