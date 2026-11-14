# OBSYRON XTM 2.0 — Mathematical Confidence Scoring Model

## 1. Overview

In automated cyber-forensic investigation, attributing an intrusion path with false certainty is dangerous. OBSYRON calculates an overall **Graph Corroboration Confidence** score $C_G \in [0.0, 1.0]$ based on three key factors:
1. Direct observation vs. heuristic inference of relationship edges.
2. Temporal corroboration consistency across normalized timestamps.
3. Signal density along the multi-hop kill chain.

---

## 2. Edge-Level Confidence Formula

For each edge $e = (u, v) \in E$, the confidence $C(e)$ is determined as follows:

$$
C(e) =
\begin{cases}
C_{\text{base}}(e) \cdot \Phi_{\text{temporal}}(e), & \text{if } e \text{ is directly observed in logs} \\
C_{\text{inferred\_base}} \cdot \Psi_{\text{gap\_penalty}}(e), & \text{if } e \text{ is heuristically bridged}
\end{cases}
$$

Where:
- $C_{\text{base}}(e) = 0.96$ for high-severity malicious signals with corroborating endpoint/network evidence.
- $C_{\text{base}}(e) = 0.75$ for routine background enterprise interactions.
- $\Phi_{\text{temporal}}(e) \in [0.95, 1.00]$ rewards edges that align with strict chronologically consistent causal order.
- $C_{\text{inferred\_base}} = 0.65$ represents the maximum possible baseline for an unobserved, inferred bridge.
- $\Psi_{\text{gap\_penalty}}(e)$ applies an exponential decay based on the temporal window $\Delta T$ spanning the gap:
  $$\Psi_{\text{gap\_penalty}}(e) = \exp\left(-\frac{\Delta T}{\tau}\right)$$
  Where $\tau = 600\text{ seconds}$ (10 minutes). For a 4-minute gap, $\Psi \approx 0.67$, giving $C(e) \approx 0.59 - 0.61$.

---

## 3. Overall Graph Confidence Formula

The global graph corroboration score $C_G$ is evaluated as the edge-weighted average across all malicious path edges $E_{\text{malicious}}$:

$$
C_G = \frac{1}{|E_{\text{malicious}}|} \sum_{e \in E_{\text{malicious}}} C(e)
$$

### Comparative Confidence Scenarios

| Scenario | Direct Logs Present | Inferred Hops | Calculated $C_G$ | Status |
|---|---|---|---|---|
| **Complete 6-Step APT Telemetry** | 6 / 6 | 0 | **94.2% – 95.1%** | Fully Corroborated |
| **Telemetry Drop (Privilege Esc Missing)** | 5 / 6 | 1 | **88.9% – 89.3%** | Partially Inferred |
| **Double Telemetry Drop** | 4 / 6 | 2 | **81.4% – 83.0%** | Elevated Uncertainty |
| **Baseline Benign Traffic Only** | 0 Malicious | 0 | **75.0%** | Routine Enterprise |

---

## 4. Uncertainty Communication in the UI

OBSYRON visually communicates confidence to prevent operator complacency:
- **Edges with $C(e) \ge 0.90$:** Solid critical red lines (`#EF4444`, 2.5px width).
- **Edges with $C(e) < 0.70$ (Inferred):** Dashed amber lines (`#F59E0B`, `[6, 4]` dash pattern, 2px width) labeled with an explicit `⚠️ INFERRED_LATERAL_BRIDGE (59%)` tag.
- **KPI Card:** Dynamic color coding transitions from Cyan (`CORROBORATED`, 94%+) to Amber (`UNCERTAINTY DETECTED`, <90%).

