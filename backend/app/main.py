import warnings
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.ai.engine import ai_engine
from app.database import init_db
from app.api import tasks, scans, reports, ws, export, cve, attack, recon, settings, pocs, verify, correlation, templates
from app.middleware.exceptions import global_exception_handler
from app.middleware.request_logger import request_logger_middleware
from app.utils.logger import get_logger

logger = get_logger("wyqyan")

APP_VERSION = "2.0.0"


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
