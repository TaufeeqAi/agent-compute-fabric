"""Checkout convenience: ``python apps/host-cli/main.py host info`` without installing the package.

An installed ``acf-local`` (``uv tool install ./apps/host-cli``) is the normal way to run the client; this
shim only puts ``src/`` on the import path so a fresh clone works.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from acf_cli.main import main

if __name__ == "__main__":
    main()
