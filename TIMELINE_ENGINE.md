# OBSYRON XTM 2.0 — Timeline Engine & Clock Skew Normalization

## 1. Problem: Temporal Distortion in Distributed Forensics

In distributed enterprise environments, host clocks drift constantly. For example:
- Workstation `wkst-04-dev` is skewed by $+12$ seconds.
- Domain Controller `dc-01` is skewed by $-7$ seconds.
- Production Database `db-prod-01` is skewed by $-5$ seconds.

If an analyst inspects raw timestamps:
1. `dc-01` reports LDAP query at `01:15:53`.
2. `wkst-04-dev` reports user execution at `01:16:12`.
Raw timestamps falsely indicate that the domain controller responded *19 seconds before* the user executed the query, inverting causal reality!

---

## 2. Mathematical Clock Skew Compensation

OBSYRON maintains a per-host clock skew vector $\Delta t_{\text{host}} \in \mathbb{R}$.

For each raw log $L$:
$$t_{\text{norm}}(L) = t_{\text{raw}}(L) - \Delta t_{\text{host}}(L.\text{host})$$

```python
def normalize_logs(raw_logs: list) -> list:
    normalized = []
    for log in raw_logs:
        log = dict(log)
        raw_dt = datetime.fromisoformat(log["raw_timestamp"])
        skew_sec = log.get("host_skew_sec", 0) or 0
        norm_dt = raw_dt - timedelta(seconds=skew_sec)
        log["normalized_timestamp"] = norm_dt.isoformat()
        log["skew_corrected_sec"]   = -skew_sec
        normalized.append(log)

    normalized.sort(key=lambda x: x["normalized_timestamp"])
    return normalized
```

Once corrected, causal ordering is restored:
- `wkst-04-dev` executed query: `01:16:12 - 12s = 01:16:00`.
- `dc-01` received & logged query: `01:15:53 - (-7s) = 01:16:00`.
Causality is perfectly reconciled.

---

## 3. Dynamic Snapshot Slicing

The timeline engine allows dynamic temporal slicing:
$$\text{Snapshot}(T) = \{ L \in \text{Logs} \mid t_{\text{norm}}(L) \le T \}$$

When an operator drags the timeline slider:
1. The client requests `/api/graph/snapshot?timestamp=T`.
2. The engine filters the normalized event list.
3. NetworkX rebuilds the graph up to time $T$.
4. Cytoscape.js updates the canvas, allowing the investigator to observe the attack unfolding in real time.
