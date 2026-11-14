"""
OBSYRON XTM 2.0 — Modular FastAPI Application
HackInnovision 2026 (Track C: Cyber Investigation & Attack Graph Reconstruction)
"""

import sys, os
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

# Import root app instance to guarantee shared state, session cache, and unified handlers
from app import app as main_app

app = main_app

if __name__ == "__main__":
    import uvicorn
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("backend.app.main:app", host=host, port=port, reload=False)
