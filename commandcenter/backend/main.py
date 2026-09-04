"""THE VOID Command Center — FastAPI application entrypoint.

Binds exclusively to 127.0.0.1. Serves REST + WebSocket, and in production
serves the built frontend static assets from the same process.
"""

from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path

# Ensure project root is importable
_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from fastapi import FastAPI, Request, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from commandcenter.backend.config import load_settings
from commandcenter.backend.routers import (
    attack_graph,
    boneyard,
    c2,
    demo,
    insights,
    report,
    status,
    targets,
    warlog,
)
from commandcenter.backend.services.bridge import get_bridge
from commandcenter.backend.services.poller import EventPoller
from commandcenter.backend.ws.hub import websocket_endpoint

try:
    from commandcenter import __version__ as _CC_VERSION
except Exception:  # pragma: no cover
    _CC_VERSION = "1.0.0"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("void.commandcenter")


def create_app() -> FastAPI:
    settings = load_settings()
    poller: EventPoller | None = None

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        nonlocal poller
        # Eager-init bridge so first request is fast
        bridge = get_bridge()
        logger.info(
            "Command center starting (host=%s port=%s degraded=%s)",
            settings.host,
            settings.port,
            bridge.degraded or "none",
        )
        poller = EventPoller(
            bridge=bridge,
            warlog_interval=settings.warlog_poll_interval,
            c2_interval=settings.c2_poll_interval,
            engagement_interval=settings.engagement_poll_interval,
            integrity_interval=settings.integrity_poll_interval,
        )
        await poller.start()
        yield
        if poller:
            await poller.stop()
        logger.info("Command center stopped")

    app = FastAPI(
        title="THE VOID Command Center",
        description="Localhost operator console for THE VOID red team platform",
        version=_CC_VERSION,
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )

    allowed_origins = set(settings.cors_origins)
    allowed_origins.update(
        {
            f"http://127.0.0.1:{settings.port}",
            f"http://localhost:{settings.port}",
        }
    )

    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["127.0.0.1", "localhost", "[::1]"],
        www_redirect=False,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=sorted(allowed_origins),
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def protect_local_browser_boundary(request: Request, call_next):
        """Block cross-site mutations and add browser hardening headers."""
        origin = request.headers.get("origin")
        if (
            request.method in {"POST", "PUT", "PATCH", "DELETE"}
            and origin
            and origin not in allowed_origins
        ):
            return JSONResponse(
                {"detail": "Cross-origin mutation rejected"},
                status_code=403,
            )

        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        )
        if not request.url.path.startswith("/api/"):
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; base-uri 'none'; object-src 'none'; "
                "frame-ancestors 'none'; form-action 'self'; "
                "script-src 'self'; style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; font-src 'self'; connect-src 'self'"
            )
        return response

    # REST routers
    app.include_router(status.router)
    app.include_router(targets.router)
    app.include_router(boneyard.router)
    app.include_router(attack_graph.router)
    app.include_router(c2.router)
    app.include_router(warlog.router)
    app.include_router(report.router)
    app.include_router(insights.router)
    app.include_router(demo.router)

    @app.get("/api/health")
    async def health():
        bridge = get_bridge()
        return {
            "ok": True,
            "host": settings.host,
            "port": settings.port,
            "degraded": bridge.degraded,
        }

    @app.websocket("/ws/live")
    async def ws_live(websocket: WebSocket):
        origin = websocket.headers.get("origin")
        if origin and origin not in allowed_origins:
            await websocket.close(code=1008, reason="Origin not allowed")
            return
        await websocket_endpoint(websocket)

    # Production: serve frontend static build if present
    static_dir = settings.static_dir
    if static_dir.is_dir() and (static_dir / "index.html").is_file():
        assets = static_dir / "assets"
        if assets.is_dir():
            app.mount("/assets", StaticFiles(directory=str(assets)), name="assets")

        @app.get("/")
        async def spa_index():
            return FileResponse(static_dir / "index.html")

        @app.get("/{full_path:path}")
        async def spa_fallback(full_path: str):
            # Don't shadow API/WS — unknown API paths are real 404s (JSON).
            if full_path.startswith("api") or full_path.startswith("ws"):
                return JSONResponse({"detail": "Not found"}, status_code=404)
            # Resolve and confine to static_dir — prevent path traversal
            candidate = (static_dir / full_path).resolve()
            try:
                candidate.relative_to(static_dir.resolve())
            except ValueError:
                return {"detail": "Not found"}
            if candidate.is_file():
                return FileResponse(candidate)
            return FileResponse(static_dir / "index.html")
    else:

        @app.get("/")
        async def root_dev():
            return {
                "service": "THE VOID Command Center",
                "status": "api-only",
                "hint": "Frontend not built. Run ./scripts/dev.sh or ./scripts/build.sh",
                "docs": "/api/docs",
                "ws": "/ws/live",
            }

    return app


app = create_app()


def main() -> None:
    settings = load_settings()
    settings.assert_localhost()
    import uvicorn

    uvicorn.run(
        "commandcenter.backend.main:app",
        host=settings.host,
        port=settings.port,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
