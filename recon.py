"""Entry point: --gui launches the Tkinter GUI, otherwise the CLI takes over."""
from __future__ import annotations

import sys

if "--gui" in sys.argv:
    sys.argv.remove("--gui")
    from gui.app import launch
    launch()
else:
    from recon.cli import app
    app()
