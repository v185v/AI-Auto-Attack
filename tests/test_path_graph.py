from backend.analysis.path_graph import build_attack_path_graph


def test_build_attack_path_graph_returns_chains_and_risk() -> None:
    payload = build_attack_path_graph(
        nodes=[
            {
                "id": "a",
                "target": "10.20.1.8",
                "status": "completed",
                "depends_on": [],
                "summary": {"finding_count": 2, "verified_findings": 1},
            },
            {
                "id": "b",
                "target": "10.20.1.9",
                "status": "completed",
                "depends_on": ["a"],
                "summary": {"finding_count": 1, "verified_findings": 1},
            },
            {
                "id": "c",
                "target": "10.20.1.10",
                "status": "completed",
                "depends_on": ["b"],
                "summary": {"finding_count": 1, "verified_findings": 0},
            },
        ]
    )

    assert payload["summary"]["total_nodes"] == 3
    assert payload["summary"]["total_edges"] == 2
    assert payload["summary"]["total_paths"] == 1
    assert payload["paths"][0]["node_ids"] == ["a", "b", "c"]
    assert payload["paths"][0]["risk_score"] > 0
    stages = {item["id"]: item["stage"] for item in payload["nodes"]}
    assert stages["a"] == "initial_exposure"
    assert stages["b"] == "lateral_movement"
    assert stages["c"] == "business_impact"


def test_build_attack_path_graph_handles_empty_input() -> None:
    payload = build_attack_path_graph(nodes=[])
    assert payload["summary"]["total_nodes"] == 0
    assert payload["paths"] == []
