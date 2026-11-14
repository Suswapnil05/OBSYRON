# OBSYRON XTM 2.0 — Deployment & Hosting Guide

OBSYRON supports dual operational environments: 100% offline local-first workstations and cloud serverless hosting on Vercel.

---

## 1. Local-First Air-Gapped Deployment

For active forensics on classified networks, deploy locally:

### Prerequisites
- Python 3.11, 3.12, or 3.13.
- Modern web browser (Chrome, Edge, Firefox, Brave).

### Setup Commands
```bash
# Clone the repository
git clone https://github.com/Suswapnil05/OBSYRON.git
cd OBSYRON

# Install dependencies
pip install -r requirements.txt

# Start the server
python app.py
```
Or simply double-click `start_obsyron.bat` on Windows.
Access the SOC cockpit at: `http://localhost:8000/`.

---

## 2. Vercel Serverless Cloud Deployment

OBSYRON is configured for automated Git-integrated deployment on Vercel:

### Architecture Configuration
- **`api/index.py`:** Serverless entrypoint exporting the ASGI `app` object.
- **`public/`:** Static directory containing `index.html`, `login.html`, `favicon.ico`, and `static/*` served globally by Vercel Edge CDN with zero cold-start latency.
- **`vercel.json`:**
  ```json
  {
    "$schema": "https://openapi.vercel.sh/vercel.json",
    "cleanUrls": true,
    "rewrites": [
      {
        "source": "/api/(.*)",
        "destination": "/api/index.py"
      },
      {
        "source": "/login",
        "destination": "/login.html"
      }
    ]
  }
  ```

### Resolving Vercel Serverless Routing Caveats
When Vercel rewrites `/api/*` to `api/index.py`, it injects specific headers:
1. `x-matched-path`: The original user-requested path.
2. In `app.py`, `vercel_path_normalizer` middleware checks `x-matched-path` and resets `request.scope["path"]`.
3. Route handlers are dual-bound (`@app.post("/api/analyze")` and `@app.post("/analyze")`) so requests succeed whether or not `/api` was stripped by reverse proxies.

---

## 3. Environment Variables (Optional)

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `8000` | Port for local uvicorn server |
| `VERCEL` | `None` (autodetected) | Enables serverless runtime optimizations |
| `LOG_LEVEL` | `info` | Logging verbosity (`debug`, `info`, `warning`) |

