"""pytest only (the suite itself is plain unittest and needs nothing installed).

This directory is a Hermes plugin package: its ``__init__.py`` imports Hermes and is not a
test package. pytest would import it before running anything under it, so that one import is
turned off here; ``pytest`` and ``python -m unittest discover -s tests`` then run the same tests.
"""
from pathlib import Path

_ROOT = Path(__file__).resolve().parent


def pytest_collection_modifyitems(session, config, items):
    seen = set()
    for item in items:
        for node in item.listchain():
            if id(node) not in seen and type(node).__name__ == "Package" and Path(str(node.path)).resolve() == _ROOT:
                node.setup = lambda: None
            seen.add(id(node))
