# SPDX-License-Identifier: GPL-2.0-or-later
"""Tests for :mod:`uru_doctor_cli.config` and the checked-in ``uru-doctor.toml``.

The shipped file documents the whole tree -- the library's sections and the
CLI's ``paths``/``launchpad``/``queue`` -- so it is validated here, against
the CLI's model. Loading it through the library's plain ``Config`` must fail:
every model is ``extra="forbid"``, and that refusal is what keeps a section
nobody reads from looking like a setting.

The guard works in both directions and forces a decision: every option in the
file must be real and must equal the default, and every field in the model must
be either documented in the file or listed in it as not yet honoured. Adding a
config field without choosing one of those two fails.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest
from uru_doctor_cli.config import CliConfig, load_cli_config

from uru_doctor.config import Config, load_config

PROJECT = Path(__file__).resolve().parents[2]
SHIPPED = PROJECT / "uru-doctor.toml"


def _model_fields() -> set[str]:
    """Every ``section.option`` the model defines, except ``source_path``."""
    out: set[str] = set()
    for section, field in CliConfig.model_fields.items():
        if section == "source_path":
            continue
        annotation = field.annotation
        inner = getattr(annotation, "model_fields", None)
        if inner is None:
            continue
        out.update(f"{section}.{name}" for name in inner)
    return out


def _documented() -> set[str]:
    """``section.option`` pairs the shipped file actually sets."""
    raw = tomllib.loads(SHIPPED.read_text())
    return {
        f"{section}.{option}"
        for section, body in raw.items()
        if isinstance(body, dict)
        for option in body
    }


def _declared_unimplemented() -> set[str]:
    """Names the file lists as defined but not honoured.

    Parsed from the commented block at the end rather than kept as a second
    list in Python, so that the file remains the single statement of what is
    and is not wired up.
    """
    text = SHIPPED.read_text()
    marker = "# Defined but not yet honoured"
    assert marker in text, "the shipped config must keep its unimplemented list"
    tail = text[text.index(marker) :]
    names: set[str] = set()
    for match in re.finditer(r"^#\s{3}([a-z_]+\.[a-z_*]+)", tail, re.MULTILINE):
        names.add(match.group(1))
    return names


class TestShippedFile:
    def test_exists_and_is_valid_toml(self) -> None:
        assert SHIPPED.is_file(), "uru-doctor.toml should be checked in"
        tomllib.loads(SHIPPED.read_text())

    def test_loads(self) -> None:
        config = load_cli_config(SHIPPED)
        assert config.source_path == SHIPPED

    def test_the_library_model_refuses_it(self) -> None:
        """The boundary in one assertion.

        The shipped file carries the CLI's sections, so the library's
        ``extra="forbid"`` model must refuse it. If this ever passes, the
        library has silently grown a section it does not read.
        """
        with pytest.raises(ValueError, match="paths"):
            load_config(SHIPPED, model=Config)

    def test_documents_only_the_real_defaults(self) -> None:
        """The whole point: the file must not describe a tool that does not exist."""
        shipped = load_cli_config(SHIPPED)
        defaults = CliConfig()
        for name in _documented():
            section, option = name.split(".", 1)
            mine = getattr(getattr(shipped, section), option)
            theirs = getattr(getattr(defaults, section), option)
            assert mine == theirs, f"{name}: file says {mine!r}, code says {theirs!r}"

    def test_every_documented_option_exists(self) -> None:
        unknown = _documented() - _model_fields()
        assert not unknown, f"documented but not a real option: {sorted(unknown)}"

    def test_every_field_is_either_documented_or_declared_unimplemented(self) -> None:
        """Adding a config field must force a decision.

        Either wire it up and document it here, or record it in the file's
        "defined but not yet honoured" list. Silence is the one outcome this
        test refuses, because a silent option is how the previous
        ``wanted_attachments`` list came to contradict the code for months
        without anyone noticing.
        """
        declared = _declared_unimplemented()
        wildcard_sections = {n.split(".", 1)[0] for n in declared if n.endswith(".*")}
        undecided = {
            name
            for name in _model_fields()
            if name not in _documented()
            and name not in declared
            and name.split(".", 1)[0] not in wildcard_sections
        }
        assert not undecided, (
            "these config fields are neither documented nor declared "
            f"unimplemented in uru-doctor.toml: {sorted(undecided)}"
        )

    def test_unimplemented_list_names_real_fields(self) -> None:
        """The list must not accumulate names that no longer exist."""
        fields = _model_fields()
        sections = {n.split(".", 1)[0] for n in fields}
        for name in _declared_unimplemented():
            if name.endswith(".*"):
                assert name.split(".", 1)[0] in sections, name
            else:
                assert name in fields, f"listed as unimplemented but not a field: {name}"

    def test_documented_and_unimplemented_do_not_overlap(self) -> None:
        overlap = _documented() & _declared_unimplemented()
        assert not overlap, f"both documented and declared unimplemented: {sorted(overlap)}"

    def test_implemented_options_are_actually_consulted(self) -> None:
        """A documented option must appear somewhere outside the config modules.

        Crude -- a grep for the attribute name -- but it catches the failure
        that matters: an option described in the file that no code reads.
        """
        source = "\n".join(
            path.read_text()
            for tree in (PROJECT / "src" / "uru_doctor", PROJECT / "cli" / "src" / "uru_doctor_cli")
            for path in tree.rglob("*.py")
            if path.name != "config.py"
        )
        missing = [name for name in _documented() if name.split(".", 1)[1] not in source]
        assert not missing, f"documented but unread: {sorted(missing)}"


class TestVersioning:
    """The CLI's version must be stated consistently in every place.

    Same drift risk as the library, one extra leg: the dependency the CLI
    declares on the library must actually accept the library in this tree, or
    a release ships a frontend that refuses its own backend.
    """

    def test_pyproject_matches_package_version(self) -> None:
        import uru_doctor_cli

        raw = tomllib.loads((PROJECT / "cli" / "pyproject.toml").read_text())
        assert raw["project"]["version"] == uru_doctor_cli.__version__

    def test_changelog_covers_the_current_version(self) -> None:
        import uru_doctor_cli

        changelog = (PROJECT / "CHANGELOG.md").read_text()
        released = re.findall(r"^## \[(\d[^]]*)\]", changelog, re.MULTILINE)
        assert uru_doctor_cli.__version__ in released, (
            f"no changelog entry for CLI {uru_doctor_cli.__version__}"
        )

    def test_library_requirement_accepts_the_workspace_library(self) -> None:
        """The pin must not exclude the library it is developed against.

        Parsed by hand rather than via ``packaging`` so the test does not
        depend on a package the library deliberately does not.
        """
        import uru_doctor

        raw = tomllib.loads((PROJECT / "cli" / "pyproject.toml").read_text())
        (requirement,) = [
            d for d in raw["project"]["dependencies"] if d.startswith("uru-doctor")
        ]
        specifiers = re.findall(r"(>=|<=|==|~=|<|>)\s*([0-9.]+)", requirement)
        assert specifiers, f"uru-doctor is unpinned: {requirement}"
        current = tuple(int(p) for p in uru_doctor.__version__.split("."))
        for op, bound in specifiers:
            bound_v = tuple(int(p) for p in bound.split("."))
            if op == ">=":
                assert current >= bound_v, requirement
            elif op == "<":
                assert current < bound_v, requirement
            elif op == "==":
                assert current == bound_v, requirement


class TestDocstring:
    def test_header_precedes_the_docstring(self) -> None:
        """A header inserted after the docstring would blank ``__doc__``.

        Several modules print their own docstring as help text, so this is
        load-bearing rather than stylistic.
        """
        import uru_doctor_cli.cli
        import uru_doctor_cli.lp

        import uru_doctor.report

        for module in (uru_doctor_cli.cli, uru_doctor_cli.lp, uru_doctor.report):
            assert module.__doc__, f"{module.__name__} lost its docstring"
