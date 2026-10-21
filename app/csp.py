"""Content-Security-Policy built by the app (strict script-src without 'unsafe-inline' / 'unsafe-eval').

- every response gets a fresh nonce (request.state.csp_nonce); inline <script> blocks in templates carry it,
  and htmx copies it to scripts that arrive in swapped fragments (htmx-config inlineScriptNonce);
- inline on*="..." handlers are allowed by their SHA-256 ('unsafe-hashes'): the hashes are computed from the
  templates at startup, so a new handler is covered automatically as long as it has no template values inside;
- CSP_MODE=report (default) sends Content-Security-Policy-Report-Only: nothing is blocked, the browser posts
  violations to /csp-report (logged and kept in Redis adp:csp:reports). CSP_MODE=enforce blocks.
"""
from __future__ import annotations

import base64
import hashlib
import html
import json
import logging
import os
import re
import secrets
import time
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import Response
from starlette.middleware.base import BaseHTTPMiddleware

log = logging.getLogger(__name__)
router = APIRouter()

_TEMPLATES = Path(__file__).parent / "templates"
_HANDLER_RE = re.compile(r'\son[a-z]+="([^"]*)"', re.IGNORECASE)
_REPORTS_KEY = "adp:csp:reports"
_FRAME_ANCESTORS = "'self' http://dashboard.jsq.home:8787 http://127.0.0.1:8787 http://localhost:8787 https://dashboard.jsq.home:8787"


def _handler_hashes() -> list[str]:
    found: set[str] = set()
    for f in _TEMPLATES.rglob("*.html"):
        for m in _HANDLER_RE.finditer(f.read_text(encoding="utf-8")):
            body = m.group(1)
            if "{{" in body or "{%" in body:
                log.warning("CSP: обработчик с шаблонным значением не хешируется: %s: %s", f.name, body[:80])
                continue
            digest = hashlib.sha256(html.unescape(body).encode("utf-8")).digest()
            found.add("'sha256-" + base64.b64encode(digest).decode("ascii") + "'")
    return sorted(found)


_HASHES = " ".join(_handler_hashes())


def _mode() -> str:
    return (os.getenv("CSP_MODE") or "report").strip().lower()


def policy(nonce: str) -> str:
    return (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}' 'unsafe-hashes' {_HASHES}; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; "
        f"frame-ancestors {_FRAME_ANCESTORS}; object-src 'none'; base-uri 'self'; form-action 'self'; "
        "report-uri /csp-report"
    )


class CSPMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        nonce = secrets.token_urlsafe(16)
        request.state.csp_nonce = nonce
        response = await call_next(request)
        if (response.headers.get("content-type") or "").startswith("text/html"):
            header = "Content-Security-Policy" if _mode() == "enforce" else "Content-Security-Policy-Report-Only"
            response.headers[header] = policy(nonce)
        return response


@router.post("/csp-report")
async def csp_report(request: Request):
    raw = (await request.body())[:8192]
    try:
        rep = json.loads(raw or b"{}").get("csp-report", {})
    except Exception:
        rep = {}
    item = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "directive": rep.get("violated-directive") or rep.get("effective-directive"),
        "blocked": rep.get("blocked-uri"),
        "doc": (rep.get("document-uri") or "")[:200],
        "src": (rep.get("source-file") or "")[:200],
        "line": rep.get("line-number"),
        "sample": (rep.get("script-sample") or "")[:120],
    }
    log.warning("CSP violation: %s", item)
    try:
        from .session import _redis

        r = _redis()
        r.lpush(_REPORTS_KEY, json.dumps(item, ensure_ascii=False))
        r.ltrim(_REPORTS_KEY, 0, 499)
    except Exception:
        pass
    return Response(status_code=204)
