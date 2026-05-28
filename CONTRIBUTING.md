# Contributing to Deep Web Recon

## Reporting Bugs

Open an issue using the **Bug Report** template. Include:
- OS and Python version (`python --version`)
- Target domain type (e.g. shared hosting, CDN-fronted, corporate)
- Full error output from the GUI log
- Which scan sections were enabled

## Pull Requests

1. Fork the repo and create a feature branch from `main`
2. Keep scan logic in the appropriate module under `recon/`
3. Run `python DeepWebRecon.py` and verify the affected sections work end-to-end
4. Describe **why** the change is needed in the PR description — not just what it does

## Adding a New Scan Module

1. Create a new file in `recon/modules/<category>/`
2. Implement a class that inherits from `recon.modules.base.BaseModule`
3. Register it in `recon/engine.py`
4. Add a checkbox entry to `SCAN_SECTIONS` in `DeepWebRecon.py`

## Code Style

- Follow PEP 8
- No bare `except Exception: pass` — distinguish `NXDOMAIN` / `NoAnswer` / unexpected
- All public methods must have at least a one-line docstring
- No hardcoded paths, usernames, or credentials
- Validate all external input at the boundary (domain field, file paths)
