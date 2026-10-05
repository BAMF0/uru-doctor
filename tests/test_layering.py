# SPDX-License-Identifier: GPL-2.0-or-later
"""The library/frontend boundary, enforced.

``uru_doctor`` is the library: it must import without ``typer``, ``rich`` or
``httpx`` installed, and it must never reach into ``uru_doctor_cli``, the
frontend that depends on it. A single convenient import -- a progress helper,
a config class -- would dissolve the boundary, and nothing would notice until
a consumer installed the library alone and watched it fail at import time.

Parsed with :mod:`ast` rather than grepped, so a docstring that *mentions*
``rich`` does not fail the suite.
"""

from __future__ import annotations

import ast
from pathlib import Path

LIBRARY = Path(__file__).resolve().parents[1] / "src" / "uru_doctor"

#: Top-level names the library must never import. ``typer`` and ``rich`` are
#: the CLI's UI; ``httpx`` is the Launchpad client's transport; and
#: ``uru_doctor_cli`` is the frontend itself -- the edge runs one way only.
FORBIDDEN = frozenset({"typer", "rich", "httpx", "uru_doctor_cli"})


def _imported_toplevels(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".", 1)[0])
    return names


class TestLibraryBoundary:
    def test_no_library_module_imports_the_frontend_or_its_dependencies(self) -> None:
        offenders: list[str] = []
        for path in sorted(LIBRARY.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            bad = _imported_toplevels(path) & FORBIDDEN
            if bad:
                offenders.append(f"{path.relative_to(LIBRARY)}: {sorted(bad)}")
        assert not offenders, "library modules importing across the boundary:\n" + "\n".join(
            offenders
        )

    def test_the_library_imports_with_only_pydantic(self) -> None:
        """The dependency list is the other half of the promise."""
        import tomllib

        pyproject = LIBRARY.parents[1] / "pyproject.toml"
        dependencies = tomllib.loads(pyproject.read_text())["project"]["dependencies"]
        assert dependencies == ["pydantic>=2.7"]
