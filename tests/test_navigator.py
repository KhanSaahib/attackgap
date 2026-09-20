from attackgap.models import Coverage, TechniqueResult
from attackgap.navigator import build_layer


def test_build_layer_shape_and_scores():
    results = {
        "T1059.001": TechniqueResult(
            technique_id="T1059.001",
            coverage=Coverage.DETECTED_VISIBLE,
            rules=["rule a"],
            reason="ok",
        ),
        "T1499": TechniqueResult(
            technique_id="T1499",
            coverage=Coverage.NO_COVERAGE,
            reason="nothing",
        ),
    }
    layer = build_layer(results)

    assert layer["domain"] == "enterprise-attack"
    assert len(layer["techniques"]) == 2
    by_id = {t["techniqueID"]: t for t in layer["techniques"]}
    assert by_id["T1059.001"]["score"] == 100
    assert by_id["T1499"]["score"] == 0
    assert "rule a" in by_id["T1059.001"]["comment"]
    assert len(layer["legendItems"]) == 4
