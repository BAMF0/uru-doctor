# SPDX-License-Identifier: GPL-2.0-or-later
"""Tests for :mod:`uru_doctor.config` and the checked-in ``uru-doctor.toml``.

The point of these is to stop the shipped file and the code drifting apart.
Documented defaults that no longer match the real ones are worse than no file,
because someone will read them and plan around them.

The guard works in both directions and forces a decision: every option in the
file must be real and must equal the default, and every field in the model must
be either documented in the file or listed in it as not yet honoured. Adding a
config field without choosing one of those two fails.
"""

from __future__ import annotations

import re
import tomllib
import traceback
from pathlib import Path

import pytest

from uru_doctor.config import (
    DEFAULT_CONFIG_FILENAMES,
    Config,
    find_config,
    load_config,
)

PROJECT = Path(__file__).resolve().parents[1]
SHIPPED = PROJECT / "uru-doctor.toml"


def _model_fields() -> set[str]:
    """Every ``section.option`` the model defines, except ``source_path``."""
    out: set[str] = set()
    for section, field in Config.model_fields.items():
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

    def test_is_discoverable_by_name(self) -> None:
        assert SHIPPED.name in DEFAULT_CONFIG_FILENAMES

    def test_loads(self) -> None:
        config = load_config(SHIPPED)
        assert config.source_path == SHIPPED

    def test_documents_only_the_real_defaults(self) -> None:
        """The whole point: the file must not describe a tool that does not exist."""
        shipped = load_config(SHIPPED)
        defaults = Config()
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
        """A documented option must appear somewhere outside config.py.

        Crude -- a grep for the attribute name -- but it catches the failure
        that matters: an option described in the file that no code reads.
        """
        source = "\n".join(
            path.read_text()
            for path in (PROJECT / "src" / "uru_doctor").rglob("*.py")
            if path.name != "config.py"
        )
        missing = [name for name in _documented() if name.split(".", 1)[1] not in source]
        assert not missing, f"documented but unread: {sorted(missing)}"


class TestLoading:
    def test_absent_config_is_valid(self, tmp_path: Path) -> None:
        assert load_config(None, search=False) == Config()

    def test_explicit_missing_path_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_config(tmp_path / "nope.toml")

    def test_unknown_key_is_rejected(self, tmp_path: Path) -> None:
        """Config models forbid extras, so a typo cannot be silently ignored."""
        path = tmp_path / "uru-doctor.toml"
        path.write_text("[paths]\nstate_dirr = 'x'\n")
        with pytest.raises(ValueError, match="state_dirr"):
            load_config(path)

    def test_partial_config_keeps_other_defaults(self, tmp_path: Path) -> None:
        path = tmp_path / "uru-doctor.toml"
        path.write_text("[report]\nmax_cascade_shown = 3\n")
        config = load_config(path)
        assert config.report.max_cascade_shown == 3
        assert config.report.top_packages == Config().report.top_packages
        assert config.dedup == Config().dedup

    def test_source_path_is_not_settable_from_the_file(self, tmp_path: Path) -> None:
        """It records where the config came from, so the file cannot claim it."""
        path = tmp_path / "uru-doctor.toml"
        path.write_text("source_path = '/somewhere/else'\n")
        assert load_config(path).source_path == path

    def test_find_walks_upward(self, tmp_path: Path) -> None:
        (tmp_path / "uru-doctor.toml").write_text("")
        nested = tmp_path / "a" / "b" / "c"
        nested.mkdir(parents=True)
        assert find_config(nested) == tmp_path / "uru-doctor.toml"

    def test_find_returns_none_when_absent(self, tmp_path: Path) -> None:
        assert find_config(tmp_path) is None

    def test_llm_section_is_refused_outright(self, tmp_path: Path) -> None:
        """``[llm]`` is gone from the code, so it must be an error, not ignored.

        It was previously a real section carrying a model configuration, listed
        in the shipped file as unimplemented. Silently accepting it now would
        let someone write a config expecting a title to be rewritten and get a
        deterministic one with no indication why.
        """
        path = tmp_path / "uru-doctor.toml"
        path.write_text('[llm]\nprovider = "ollama"\n')
        with pytest.raises(ValueError, match="llm"):
            load_config(path)

    def test_rejected_values_are_not_echoed(self, tmp_path: Path) -> None:
        """A refusal must name the field, never quote what was in it.

        pydantic's default message embeds ``input_value=``, and the CLI prints
        the whole message to stderr. A credential parked in a section this tool
        does not recognise would then be echoed into a terminal, a CI log, or a
        bug report pasted by someone asking why their config broke. Removing
        the ``[llm]`` model is what exposed this: the section used to have a
        hand-written validator that deliberately did not quote the value, and
        falling back to the generic extra-forbidden path started quoting it.

        Checked against the traceback as well as the message, because
        ``raise ... from exc`` would put the original straight back into a
        crash report.
        """
        path = tmp_path / "uru-doctor.toml"
        path.write_text('[llm]\napi_key = "sk-must-not-appear"\n')
        with pytest.raises(ValueError) as caught:
            load_config(path)
        rendered = "".join(
            traceback.format_exception(type(caught.value), caught.value, caught.value.__traceback__)
        )
        assert "sk-must-not-appear" not in str(caught.value)
        assert "sk-must-not-appear" not in rendered
        # Still useful: it has to say which field was wrong.
        assert "llm" in str(caught.value)

    def test_ambiguous_band_must_be_ordered(self, tmp_path: Path) -> None:
        path = tmp_path / "uru-doctor.toml"
        path.write_text("[dedup]\nambiguous_low = 0.9\nambiguous_high = 0.2\n")
        with pytest.raises(ValueError):
            load_config(path)


class TestLicensing:
    """The project's licence must be stated consistently in every place.

    Three places can disagree: the ``LICENSE`` file, the ``pyproject.toml``
    metadata, and the per-file SPDX headers. A new module added without a
    header is the easy mistake, so it fails here rather than at packaging time.

    GPL-2+ is not an arbitrary choice: it matches ``ubuntu-release-upgrader``,
    whose logs this reads and whose functions it cites as provenance, so that
    code can move in either direction.
    """

    EXPECTED = "GPL-2.0-or-later"

    def test_license_file_exists_and_is_gpl2(self) -> None:
        text = (PROJECT / "LICENSE").read_text()
        assert "GNU GENERAL PUBLIC LICENSE" in text
        assert "Version 2, June 1991" in text
        # GPL-2 proper, not GPL-3: the two are not interchangeable, and
        # copying the wrong file is a silent way to relicense a project.
        assert "Version 3" not in text.split("TERMS AND CONDITIONS")[0]

    def test_pyproject_declares_the_expression(self) -> None:
        raw = tomllib.loads((PROJECT / "pyproject.toml").read_text())
        project = raw["project"]
        assert project["license"] == self.EXPECTED
        assert "LICENSE" in project["license-files"]

    def test_no_deprecated_license_classifier(self) -> None:
        """PEP 639 forbids pairing a classifier with the SPDX expression."""
        raw = tomllib.loads((PROJECT / "pyproject.toml").read_text())
        classifiers = raw["project"].get("classifiers", [])
        assert not [c for c in classifiers if c.startswith("License ::")]

    def test_every_python_file_carries_an_spdx_header(self) -> None:
        header = f"# SPDX-License-Identifier: {self.EXPECTED}"
        missing: list[str] = []
        for path in sorted(PROJECT.rglob("*.py")):
            parts = set(path.parts)
            if parts & {"__pycache__", ".venv", "build", "dist"}:
                continue
            lines = path.read_text().splitlines()[:3]
            if header not in lines:
                missing.append(str(path.relative_to(PROJECT)))
        assert not missing, f"missing SPDX header: {missing}"

    def test_header_precedes_the_docstring(self) -> None:
        """A header inserted after the docstring would blank ``__doc__``.

        Several modules print their own docstring as help text, so this is
        load-bearing rather than stylistic.
        """
        import uru_doctor.cli
        import uru_doctor.lp.read
        import uru_doctor.report

        for module in (uru_doctor.cli, uru_doctor.lp.read, uru_doctor.report):
            assert module.__doc__, f"{module.__name__} lost its docstring"
