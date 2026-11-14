# OBSYRON Architecture — Backend Architecture

## 1. Asynchronous ASGI Application Layer
The backend is built with FastAPI and Uvicorn, providing native asynchronous request handling, automatic schema validation with Pydantic v2, and sub-10ms response latency.

## 2. Serverless Adaptation Layer
To ensure complete compatibility with Vercel's `@vercel/python` serverless runtime:
1. **`vercel_path_normalizer` Middleware:** Inspects incoming `x-matched-path` and `x-original-url` headers to recover the original request path when Vercel rewrites `/api/*` to `api/index.py`.
2. **Dual-Bound Route Decorators:** All endpoints are bound to both `/api/<route>` and `/<route>`, providing complete routing redundancy across reverse proxies.
3. **Stateless Self-Bootstrapping Cache:** If serverless memory is cold, requests automatically initialize the baseline state on demand.

