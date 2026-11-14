# OBSYRON XTM 2.0 — Blast Radius Analysis

## 1. Blast Radius Quantification

While Root Cause Analysis answers *how the attacker got in*, Blast Radius Analysis answers *what assets are exposed or compromised downstream*.

OBSYRON evaluates blast radius using forward directed graph reachability:

$$
\text{BlastRadius}(v_{\text{pz}}) = \{ u \in V \mid \exists \text{ directed path from } v_{\text{pz}} \text{ to } u \text{ in } G \}
$$

In NetworkX:
```python
def get_blast_radius(G: nx.MultiDiGraph, patient_zero: str) -> dict:
    if patient_zero not in G:
        return {"count": 0, "descendants": [], "pivot_entity": "None"}

    descendants = list(nx.descendants(G, patient_zero))
    
    # Identify the highest-centrality pivot node among descendants
    centrality = nx.betweenness_centrality(G)
    pivots = sorted(descendants, key=lambda n: centrality.get(n, 0), reverse=True)
    key_pivot = pivots[0] if pivots else patient_zero

    return {
        "count": len(descendants),
        "descendants": sorted(descendants),
        "pivot_entity": key_pivot
    }
```

---

## 2. APT Campaign Blast Radius Results

When executed against the 356-log enterprise dataset:
- **Patient Zero Origin:** `185.220.101.47`
- **Total Exposed / Compromised Nodes:** `14` assets
- **Downstream Entities:**
  1. `emp_rohan` (Compromised user credential)
  2. `wkst-04-dev` (Compromised developer workstation)
  3. `dc-01` (Exposed Domain Controller via LDAP recon)
  4. `svc_ci_deploy` (Compromised CI/CD service account)
  5. `db-prod-01` (Compromised production database server)
  6. Connected service dependencies and shared network hosts.

---

## 3. Privilege-Weighted Containment Playbook

Based on the blast radius traversal, OBSYRON synthesizes a prioritized containment plan:
1. **P0 (Critical):** Network isolation of pivot node `wkst-04-dev` (breaks the lateral bridge).
2. **P0 (Critical):** Kerberos ticket invalidation & credential rotation for `svc_ci_deploy`.
3. **P1 (High):** Border firewall block and TCP session tear-down for `185.220.101.47:4444`.
4. **P1 (High):** Read-only lock and snapshot preservation for `db-prod-01`.

