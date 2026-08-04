"""The documented verdict priority IS the honesty policy — pin it.

`synthesize` sat in `__all__` with zero documentation, so the one function
encoding the policy was the one you had to read source to find. Now that the
README states the order, this test makes the README a claim the code must keep.
"""
import dataclasses

import pytest

from provmirror import Signal, synthesize
from provmirror import AUTHENTIC, SYNTHETIC, TAMPERED


def _sig(direction):
    kw = {}
    for f in dataclasses.fields(Signal):
        kw[f.name] = direction if f.name == "direction" else "test"
    return Signal(**kw)


@pytest.mark.parametrize("directions,expected", [
    ([TAMPERED, AUTHENTIC, SYNTHETIC], "TAMPERED"),
    ([TAMPERED], "TAMPERED"),
    ([AUTHENTIC, SYNTHETIC], "CONFLICTING"),
    ([SYNTHETIC], "SYNTHETIC"),
    ([AUTHENTIC], "AUTHENTIC-SIGNED"),
    ([], "UNVERIFIED"),
])
def test_documented_priority_order(directions, expected):
    assert synthesize([_sig(d) for d in directions]) == expected


def test_no_signal_is_unknown_never_fake():
    """The row the package exists for. Absence of a provenance signal is
    overwhelmingly common in authentic media too, so answering 'fake' when the
    tool simply cannot tell would be worse than having no tool."""
    verdict = synthesize([])
    assert verdict == "UNVERIFIED"
    assert "SYNTHETIC" not in verdict and "TAMPERED" not in verdict


def test_readme_table_matches_the_code():
    import re
    from pathlib import Path
    for name in ("README.md", "README_KO.md"):
        txt = (Path(__file__).resolve().parents[1] / name).read_text(encoding="utf-8")
        rows = re.findall(r'^\|\s*[1-5]\s*\|\s*`([A-Z-]+)`\s*\|', txt, re.M)
        assert rows == ["TAMPERED", "CONFLICTING", "SYNTHETIC",
                        "AUTHENTIC-SIGNED", "UNVERIFIED"], f"{name}: {rows}"
