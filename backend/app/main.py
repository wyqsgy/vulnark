import warnings
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

from contextlib import asynccontextmanager

import app.config as config_mod
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.ai.engine import ai_engine
from app.database import init_db
from app.api import tasks, scans, reports, ws, export, cve, attack, recon, settings, pocs, verify, correlation, templates
from app.middleware.exceptions import global_exception_handler
from app.middleware.request_logger import request_logger_middleware
from app.utils.logger import get_logger

logger = get_logger("wyqyan")

APP_VERSION = "2.1.0"


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    ai_engine.refresh_config()
    logger.info(f"WyqYan v{APP_VERSION} started successfully")
    yield
    logger.info("WyqYan shutting down")


app = FastAPI(
    title="WyqYan",
    description="AI驱动的框架/中间件漏洞集合自动化验证平台",
    version=APP_VERSION,
    lifespan=lifespan,
)

app.middleware("http")(request_logger_middleware)


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    """可选 API 鉴权：设置 API_TOKEN 后，/api/*（除健康检查）必须携带凭据。"""
    token = config_mod.API_TOKEN
    if token and request.url.path.startswith("/api/") and request.url.path != "/api/health":
        provided = request.headers.get("X-API-Token", "")
        if not provided:
            auth = request.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                provided = auth[7:]
        if provided != token:
            return JSONResponse(
                status_code=401,
                content={"detail": "Unauthorized: missing or invalid API token"},
                headers={"WWW-Authenticate": "Bearer"},
            )
    return await call_next(request)


app.add_exception_handler(Exception, global_exception_handler)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(tasks.router)
app.include_router(scans.router)
app.include_router(reports.router)
app.include_router(ws.router)
app.include_router(export.router)
app.include_router(cve.router)
app.include_router(attack.router)
app.include_router(recon.router)
app.include_router(settings.router)
app.include_router(pocs.router)
app.include_router(verify.router)
app.include_router(correlation.router)
app.include_router(templates.router)


@app.get("/")
def root():
    return {
        "name": "WyqYan",
        "version": APP_VERSION,
        "description": "AI驱动的框架/中间件漏洞集合自动化验证平台",
        "docs": "/docs",
    }


@app.get("/api/health")
def health():
    ai_ready = ai_engine._is_available()
    return {"status": "ok", "version": APP_VERSION, "ai_ready": ai_ready}
