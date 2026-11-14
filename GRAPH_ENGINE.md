# OBSYRON XTM 2.0 — Graph Engine Specification

## 1. NetworkX MultiDiGraph Construction

OBSYRON uses `networkx.MultiDiGraph` to represent interactions between entities. Unlike simple directed graphs, a multigraph supports multiple distinct directed edges between the same node pair, essential for modeling repeated or staged security interactions.

```python
G = nx.MultiDiGraph()

for log in normalized_logs:
    u = log["source"]
    v = log["target"]
    G.add_node(u, entity_type=log.get("entity_type", "DEVICE"), ...)
    G.add_node(v, entity_type=log.get("entity_type", "DEVICE"), ...)
    G.add_edge(u, v, action=log["action"], timestamp=log["normalized_timestamp"], ...)
```

---

## 2. Pivot Entity Identification (Betweenness Centrality)

Adversaries often use intermediate nodes to bridge isolated network segments. To identify these critical assets, OBSYRON computes Brandes' Betweenness Centrality:

$$C_B(v) = \sum_{s \ne v \ne t \in V} \frac{\sigma_{st}(v)}{\sigma_{st}}$$

Where:
- $\sigma_{st}$ is the total number of shortest paths from node $s$ to node $t$.
- $\sigma_{st}(v)$ is the number of those shortest paths that pass through node $v$.

```python
centrality_scores = nx.betweenness_centrality(G)
# Identifies wkst-04-dev as the paramount pivot node (highest betweenness score)
```

In the APT investigation dataset, `wkst-04-dev` exhibits the highest betweenness centrality, proving it served as the critical bridge between external ingress and the internal database tier.

---

## 3. Cytoscape.js Frontend Rendering Pipeline

The graph structure is converted into a Cytoscape JSON payload:

```json
{
  "nodes": [
    { "data": { "id": "wkst-04-dev", "label": "wkst-04-dev", "type": "DEVICE", "centrality": 0.38, "risk": "CRITICAL" } }
  ],
  "edges": [
    { "data": { "id": "e_3_wkst-04-dev_svc_ci_deploy", "source": "wkst-04-dev", "target": "svc_ci_deploy", "action": "PRIV_ESC", "confidence": 0.91 } }
  ]
}
```

The frontend uses Cytoscape's concentric layout, positioning critical pivot nodes centrally with peripheral assets arranged in outer rings.
