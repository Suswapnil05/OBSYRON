# OBSYRON Architecture — Graph Architecture

## 1. MultiDiGraph Modeling
Security events naturally represent directed interactions between entities (users, devices, services, endpoints). Because two entities can engage in multiple distinct interactions across time (e.g., initial authentication followed by lateral RPC access), OBSYRON implements `networkx.MultiDiGraph`.

## 2. Graph Algorithms Implemented
- **Betweenness Centrality:** Brandes' algorithm evaluating shortest paths to identify critical lateral pivot nodes.
- **Root Cause Traversal:** Backward DAG search identifying in-degree zero entities and ancestral ingress nodes via `nx.ancestors()`.
- **Blast Radius Reachability:** Forward path traversal via `nx.descendants()` computing the complete closure of reachable downstream assets.
- **Gap Bridging:** Heuristic interpolation of missing intermediate kill chain steps with penalized confidence scoring.

