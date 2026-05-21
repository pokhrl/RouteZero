# conftest.py — repo root
# Ensures the routezero package is importable even if `pip install -e .`
# hasn't been run, by adding the repo root to sys.path.
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
