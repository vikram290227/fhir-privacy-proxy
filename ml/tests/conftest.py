"""Make the ml/ sibling modules importable from tests.

The ml/ directory is not a package (no package-level __init__.py),
so pytest's default sys.path doesn't find retrain_nightly or schema
unless we add the parent explicitly.
"""

import sys
from pathlib import Path

_ML_DIR = Path(__file__).resolve().parent.parent
if str(_ML_DIR) not in sys.path:
    sys.path.insert(0, str(_ML_DIR))
