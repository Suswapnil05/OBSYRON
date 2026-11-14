# OBSYRON XTM 2.0 — Technology Stack

## 1. Technology Matrix

| Layer | Component | Version | Purpose |
|---|---|---|---|
| **Backend Runtime** | Python | 3.11+ / 3.12 / 3.13 | High-performance async runtime |
| **Web Framework** | FastAPI | 0.115+ | Async ASGI web server with OpenAPI / Swagger docs |
| **ASGI Server** | Uvicorn | 0.32+ | Production-grade lightning-fast async HTTP/1.1 server |
| **Graph Engine** | NetworkX | 3.4+ | Pure Python directed multigraph algorithms (`MultiDiGraph`) |
| **Data Validation** | Pydantic | 2.9+ | Strict type validation for REST requests and schemas |
| **Multipart Parser** | python-multipart | 0.0.12+ | Efficient streaming parser for CSV / JSON file uploads |
| **Frontend Framework** | Vanilla ES6+ | Modern Standard | Lightweight, dependency-free responsive client engine |
| **Graph Canvas** | Cytoscape.js | 3.28.1 | Hardware-accelerated interactive graph visualization canvas |
| **Design System** | Tailwind CSS & Filigran Tokens | 3.4+ CDN | Dark SOC Command Center design palette (`#0B0F19`, `#111827`) |
| **Icons & Typography** | Lucide Icons & Inter / JetBrains Mono | Google Fonts / SVG | Professional cybersecurity typography and vector glyphs |
| **Audio Synthesis** | Web Speech API | W3C Standard | Client-side autonomous voice intelligence briefings |
| **Cloud Hosting** | Vercel Serverless | @vercel/python | Zero-config serverless function deployment with Edge CDN |
| **Testing Harness** | Pytest / Python Asyncio | 8.0+ | Automated test suite verifying graph theory and API endpoints |

---

## 2. Rationale for Architectural Choices

### Why NetworkX over External Graph Databases (Neo4j / Memgraph)?
- **Zero-Cloud Air-Gapped Privacy:** Traditional graph databases require external daemon processes, network sockets, credentials, and disk persistence. In active cyber incident response, requiring a Docker cluster or cloud database adds friction and exposes sensitive evidence. NetworkX operates entirely in-memory, performing sub-5ms graph traversals with zero external dependencies.
- **Dynamic Slicing Efficiency:** NetworkX allows instant sub-graph slicing based on time-travel filters without the latency of Cypher queries.

### Why Cytoscape.js over D3.js or Vis.js?
- **Graph-Specific Performance:** Cytoscape.js is purpose-built for computational graph visualization. It natively supports directed multigraph edges, custom curve-style bezier rendering, high-performance viewport culling, and interactive lasso selection.
- **Compound Nodes & Custom Styling:** Provides declarative CSS-like stylesheets for dynamic node and edge coloring based on confidence and inference flags.

### Why FastAPI over Flask / Django?
- **Native Async & Concurrency:** FastAPI leverages Python's `asyncio` event loop and `starlette`, enabling concurrent handling of time-travel scrubbing, file uploads, and graph snapshots.
- **Pydantic Validation:** Provides automatic type enforcement, JSON serialization, and OpenAPI documentation out of the box.

---

## 3. Dependency Footprint (`requirements.txt`)

```text
fastapi>=0.115.0
uvicorn>=0.32.0
networkx>=3.4
python-multipart>=0.0.12
pydantic>=2.9.0
```
Total package size: < 15 MB. Build time on Vercel: < 3 seconds.
