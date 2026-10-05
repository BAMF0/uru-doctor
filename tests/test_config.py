# SPDX-License-Identifier: GPL-2.0-or-later
"""Tests for :mod:`uru_doctor.config`, the library's configuration tree.

Loading semantics, licensing and version consistency live here. The guard that
keeps the checked-in ``uru-doctor.toml`` and the code from drifting apart lives
in ``cli/tests/test_config.py``, because that file documents the CLI's sections
too and so must be validated against the CLI's model.
"""

from __future__ import annotations

import tomllib
import traceback
from pathlib import Path

import pytest

from uru_doctor.config import Config, find_config, load_config

PROJECT = Path(__file__).resolve().parents[1]


class TestLoading:
    def test_absent_config_is_valid(self, tmp_path: Path) -> None:
        assert load_config(None, search=False) == Config()

    def test_explicit_missing_path_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_config(tmp_path / "nope.toml")

    def test_unknown_key_is_rejected(self, tmp_path: Path) -> None:
        """Config models forbid extras, so a typo cannot be silently ignored."""
        path = tmp_path / "uru-doctor.toml"
        path.write_text("[report]\ntop_packagess = 1\n")
        with pytest.raises(ValueError, match="top_packagess"):
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


class TestVersioning:
    """The version must be stated consistently in every place.

    ``uv_build`` has no dynamic-version hook, so the version lives in
    ``pyproject.toml`` and in ``__init__.__version__``, and this class is what
    stops them drifting apart. The changelog check is the client-facing half:
    a release without an entry is a version nobody can evaluate.
    """

    def test_pyproject_matches_package_version(self) -> None:
        import uru_doctor

        raw = tomllib.loads((PROJECT / "pyproject.toml").read_text())
        assert raw["project"]["version"] == uru_doctor.__version__

    def test_changelog_covers_the_current_version(self) -> None:
        import re

        import uru_doctor

        changelog = (PROJECT / "CHANGELOG.md").read_text()
        released = re.findall(r"^## \[(\d[^]]*)\]", changelog, re.MULTILINE)
        assert released, "CHANGELOG.md has no release entries"
        assert released[0] == uru_doctor.__version__, (
            f"newest changelog entry is {released[0]}, package says {uru_doctor.__version__}"
        )
