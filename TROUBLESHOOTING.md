# OBSYRON XTM 2.0 — Troubleshooting & FAQ

## 1. Common Issues & Solutions

### Issue 1: `Port 8000 already in use (WinError 10048 / EADDRINUSE)`
- **Cause:** A previous background instance of Uvicorn or another process is holding port 8000.
- **Solution (Windows PowerShell):**
  ```powershell
  Stop-Process -Id (Get-NetTCPConnection -LocalPort 8000).OwningProcess -Force
  python app.py
  ```
- **Solution (macOS / Linux):**
  ```bash
  fuser -k 8000/tcp
  python app.py
  ```

---

### Issue 2: Vercel Serverless `404 {"detail":"Not Found"}` on `/api/analyze`
- **Cause:** Vercel's Edge Router rewrites `/api/*` to `api/index.py`, which populates `request.scope['path']` with `/api/index.py` or strips `/api`.
- **Solution in OBSYRON:**
  1. `app.py` includes `vercel_path_normalizer` middleware that inspects `x-matched-path` and restores the correct path.
  2. All route handlers are dual-bound:
     ```python
     @app.post("/api/analyze")
     @app.post("/analyze")
     ```
  3. The frontend `apiFetch()` helper automatically falls back to `/analyze` if `/api/analyze` returns 404.

---

### Issue 3: Cytoscape Graph Canvas Appears Blank
- **Cause:** Ad-blockers or content filters blocking unpkg/cdnjs CDN scripts.
- **Solution:** Cytoscape.js is loaded with secure CDN integrity hashes. Ensure your network allows loading `cdnjs.cloudflare.com` or bundle `cytoscape.min.js` locally in `static/`.

---

### Issue 4: Web Speech Audio Briefing Does Not Speak
- **Cause:** Some browsers (e.g., Chrome) block autoplaying audio until the user interacts with the page (User Activation Policy).
- **Solution:** Click the `Listen to SOC Briefing` button directly. Audio synthesis will initialize immediately.

---

### Issue 5: Custom Uploaded CSV Fails Parsing
- **Cause:** Inconsistent header naming or missing mandatory columns.
- **Solution:** Ensure your CSV contains at least `source`, `target`, and `raw_timestamp` (or `timestamp`). OBSYRON's `parse_uploaded_file()` will automatically supply default values for optional columns (`protocol`, `port`, `severity`).
