from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PathNode:
    node_id: str
    target: str
    status: str
    depends_on: tuple[str, ...]
    finding_count: int
    verified_findings: int
    risk_score: int
    stage: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.node_id,
            "target": self.target,
            "status": self.status,
            "depends_on": list(self.depends_on),
            "finding_count": self.finding_count,
            "verified_findings": self.verified_findings,
            "risk_score": self.risk_score,
            "stage": self.stage,
        }


def build_attack_path_graph(*, nodes: list[dict[str, Any]]) -> dict[str, Any]:
    if not nodes:
        return {
            "nodes": [],
            "edges": [],
            "paths": [],
            "summary": {
                "total_nodes": 0,
                "total_edges": 0,
                "total_paths": 0,
                "highest_risk_path_id": "",
                "highest_risk_score": 0,
            },
        }

    by_id = {str(item.get("id", "")): item for item in nodes if str(item.get("id", "")).strip()}
    node_ids = set(by_id.keys())
    children: dict[str, list[str]] = {node_id: [] for node_id in node_ids}
    indegree: dict[str, int] = {node_id: 0 for node_id in node_ids}
    edges: list[dict[str, Any]] = []

    for node_id, raw in by_id.items():
        depends = _depends(raw)
        for dep in depends:
            if dep not in node_ids:
                continue
            children[dep].append(node_id)
            indegree[node_id] += 1
            edges.append(
                {
                    "source": dep,
                    "target": node_id,
                    "relation": "dependency_flow",
                    "weight": 1,
                }
            )

    roots = sorted([node_id for node_id, count in indegree.items() if count == 0])
    leaves = {node_id for node_id, nodes_children in children.items() if not nodes_children}
    depth = _compute_depths(roots=roots, children=children)
    max_depth = max(depth.values()) if depth else 0

    normalized_nodes: list[PathNode] = []
    for node_id in sorted(node_ids):
        raw = by_id[node_id]
        status = str(raw.get("status", "unknown"))
        finding_count = int(raw.get("summary", {}).get("finding_count", 0))
        verified_findings = int(raw.get("summary", {}).get("verified_findings", 0))
        current_depth = depth.get(node_id, 0)
        stage = _stage_for_depth(node_id=node_id, current_depth=current_depth, max_depth=max_depth, leaves=leaves)
        risk_score = _risk_score(status=status, finding_count=finding_count, verified_findings=verified_findings)
        normalized_nodes.append(
            PathNode(
                node_id=node_id,
                target=str(raw.get("target", "")),
                status=status,
                depends_on=tuple(_depends(raw)),
                finding_count=finding_count,
                verified_findings=verified_findings,
                risk_score=risk_score,
                stage=stage,
            )
        )

    node_payload = [item.to_dict() for item in normalized_nodes]
    node_index = {item["id"]: item for item in node_payload}
    paths = _build_paths(roots=roots, children=children, node_index=node_index, leaves=leaves)

    highest = {"path_id": "", "risk_score": 0}
    for item in paths:
        if int(item.get("risk_score", 0)) > highest["risk_score"]:
            highest = {
                "path_id": str(item.get("path_id", "")),
                "risk_score": int(item.get("risk_score", 0)),
            }

    return {
        "nodes": node_payload,
        "edges": edges,
        "paths": paths,
        "summary": {
            "total_nodes": len(node_payload),
            "total_edges": len(edges),
            "total_paths": len(paths),
            "highest_risk_path_id": highest["path_id"],
            "highest_risk_score": highest["risk_score"],
        },
    }


def _depends(raw: dict[str, Any]) -> list[str]:
    depends = raw.get("depends_on", [])
    if not isinstance(depends, list):
        return []
    return [str(item).strip() for item in depends if str(item).strip()]


def _risk_score(*, status: str, finding_count: int, verified_findings: int) -> int:
    normalized = status.strip().lower()
    if normalized in {"skipped", "failed"}:
        return 0
    finding_weight = max(finding_count, 0) * 10
    verified_weight = max(verified_findings, 0) * 15
    return finding_weight + verified_weight


def _stage_for_depth(
    *,
    node_id: str,
    current_depth: int,
    max_depth: int,
    leaves: set[str],
) -> str:
    if current_depth <= 0:
        return "initial_exposure"
    if node_id in leaves or current_depth >= max_depth:
        return "business_impact"
    return "lateral_movement"


def _compute_depths(*, roots: list[str], children: dict[str, list[str]]) -> dict[str, int]:
    depth: dict[str, int] = {}
    stack: list[tuple[str, int]] = [(item, 0) for item in roots]
    while stack:
        node_id, current_depth = stack.pop(0)
        prev = depth.get(node_id, -1)
        if current_depth <= prev:
            continue
        depth[node_id] = current_depth
        for child in children.get(node_id, []):
            stack.append((child, current_depth + 1))
    return depth


def _build_paths(
    *,
    roots: list[str],
    children: dict[str, list[str]],
    node_index: dict[str, dict[str, Any]],
    leaves: set[str],
) -> list[dict[str, Any]]:
    paths: list[dict[str, Any]] = []
    path_counter = 0

    def dfs(current: str, chain: list[str]) -> None:
        nonlocal path_counter
        next_chain = chain + [current]
        next_nodes = children.get(current, [])
        if not next_nodes or current in leaves:
            path_counter += 1
            stages = [str(node_index.get(item, {}).get("stage", "unknown")) for item in next_chain]
            score = sum(int(node_index.get(item, {}).get("risk_score", 0)) for item in next_chain)
            paths.append(
                {
                    "path_id": f"path-{path_counter}",
                    "node_ids": list(next_chain),
                    "targets": [str(node_index.get(item, {}).get("target", "")) for item in next_chain],
                    "stages": stages,
                    "risk_score": score,
                    "chain_summary": _build_chain_summary(node_ids=next_chain, node_index=node_index),
                }
            )
            return
        for child in next_nodes:
            dfs(child, next_chain)

    for root in roots:
        dfs(root, [])
    paths.sort(key=lambda item: int(item.get("risk_score", 0)), reverse=True)
    return paths


def _build_chain_summary(*, node_ids: list[str], node_index: dict[str, dict[str, Any]]) -> str:
    segments = []
    for node_id in node_ids:
        node = node_index.get(node_id, {})
        stage = str(node.get("stage", "unknown"))
        target = str(node.get("target", "unknown"))
        segments.append(f"{stage}:{target}")
    return " -> ".join(segments)
