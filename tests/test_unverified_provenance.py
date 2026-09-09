from provmirror import pm, PROVENANCE_HINT


def test_plain_marker_does_not_certify_signature(tmp_path):
    path = tmp_path / "note.txt"
    path.write_bytes(b"plain text c2pa: no manifest and no signature")
    result = pm.verify(str(path), seal=False)
    assert result["verdict"] == "PROVENANCE-UNVERIFIED"
    assert result["signals"][0]["direction"] == PROVENANCE_HINT
    assert result["verification"]["signature_verified"] is False
    assert result["verification"]["authenticity_verified"] is False
    assert "yellow" in pm.badge(result)
    assert "brightgreen" not in pm.badge(result)


def test_markerless_remains_unknown():
    assert pm.synthesize([pm.c2pa_manifest_check(b"plain text")]) == "UNVERIFIED"
