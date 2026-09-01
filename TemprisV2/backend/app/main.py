# backend/app/main.py
import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.db import init_db, close_db, get_db_connection
from app.config import VULN_SYNC_ENABLED, VULN_SYNC_CHECK_INTERVAL
from app.migrations_check import ensure_migrations_applied
from app.routes.assets import router as assets_router
from app.routes.collectors import router as collectors_router
from app.routes.auth import router as auth_router
from app.routes.org import router as org_router
from app.routes.platform import router as platform_router
from app.routes.vuln_intelligence import router as vuln_intelligence_router
from app.routes.exposure import router as exposure_router
from app.target_validator import TargetValidationError
from app.vuln_intelligence.sync_engine import run_sync_loop
from app.vuln_intelligence.sync_adapters import ALL_ADAPTERS

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    ensure_migrations_applied()

    sync_task = None
    shutdown_event = None

    if VULN_SYNC_ENABLED:
        logger.info("Vulnerability intelligence background scheduler enabled (check interval: %ds)", VULN_SYNC_CHECK_INTERVAL)
        shutdown_event = asyncio.Event()
        sync_task = asyncio.create_task(
            run_sync_loop(
                get_db_connection,
                ALL_ADAPTERS,
                check_interval=VULN_SYNC_CHECK_INTERVAL,
                shutdown_event=shutdown_event,
            )
        )

    yield

    if shutdown_event is not None:
        shutdown_event.set()
        if sync_task is not None:
            try:
                await asyncio.wait_for(sync_task, timeout=5.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                sync_task.cancel()

    close_db()


app = FastAPI(
    title="Tempris V2 ASSETS Service",
    version="2.0.0",
    description="Authoritative, tenant-isolated asset inventory service for Tempris V2",
    lifespan=lifespan
)

# Cross-origin resource sharing
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.exception_handler(TargetValidationError)
async def target_validation_exception_handler(request: Request, exc: TargetValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": str(exc)}
    )

@app.get("/healthz", tags=["Health"])
def health_check():
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1;")
            cur.fetchone()
    return {"status": "ok", "service": "tempris-v2-assets"}

app.include_router(auth_router)
app.include_router(assets_router)
app.include_router(collectors_router)
app.include_router(org_router)
app.include_router(platform_router)
app.include_router(vuln_intelligence_router)
app.include_router(exposure_router)

frontend_dist = Path(__file__).resolve().parents[2] / "frontend" / "dist"
if frontend_dist.is_dir():
    @app.get("/platform-login", include_in_schema=False)
    @app.get("/platform-dashboard", include_in_schema=False)
    @app.get("/v2/platform-login", include_in_schema=False)
    @app.get("/v2/platform-dashboard", include_in_schema=False)
    def platform_frontend_entry():
        return FileResponse(frontend_dist / "index.html")

    app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="frontend")
