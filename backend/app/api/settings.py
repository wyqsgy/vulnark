import json
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.ai.engine import ai_engine
from app.database import get_db
from app.models.settings import AIModelConfig, InfoGatheringKey, SystemSettings
from app.utils.logger import get_logger

logger = get_logger("settings_api")
router = APIRouter(prefix="/api/settings", tags=["settings"])


class AIModelRequest(BaseModel):
    name: str
    provider: str
    api_base: str
    api_key: str = ""
    model_name: str
    temperature: str = "0.1"
    max_tokens: str = "4096"
    timeout: str = "60"
    is_enabled: bool = True
    is_default: bool = False


class InfoKeyRequest(BaseModel):
    platform: str
    api_key: str = ""
    email: str = ""
    is_enabled: bool = True
    extra_config: str = "{}"


class SystemSettingRequest(BaseModel):
    key: str
    value: str
    description: str = ""


# ============================================================
# AI Model Configs
# ============================================================

@router.get("/ai-models")
def list_ai_models(db: Session = Depends(get_db)):
    models = db.query(AIModelConfig).order_by(AIModelConfig.created_at.desc()).all()
    return {
        "code": 200,
        "data": [
            {
                "id": m.id,
                "name": m.name,
                "provider": m.provider,
                "api_base": m.api_base,
                "api_key": m.api_key[:8] + "****" if m.api_key else "",
                "model_name": m.model_name,
                "temperature": m.temperature,
                "max_tokens": m.max_tokens,
                "timeout": m.timeout,
                "is_enabled": m.is_enabled,
                "is_default": m.is_default,
                "created_at": str(m.created_at) if m.created_at else None,
                "updated_at": str(m.updated_at) if m.updated_at else None,
            }
            for m in models
        ],
    }


@router.post("/ai-models")
def create_ai_model(req: AIModelRequest, db: Session = Depends(get_db)):
    if req.is_default:
        db.query(AIModelConfig).filter(AIModelConfig.is_default == True).update({"is_default": False})

    model = AIModelConfig(
        name=req.name,
        provider=req.provider,
        api_base=req.api_base,
        api_key=req.api_key,
        model_name=req.model_name,
        temperature=req.temperature,
        max_tokens=req.max_tokens,
        timeout=req.timeout,
        is_enabled=req.is_enabled,
        is_default=req.is_default,
    )
    db.add(model)
    db.commit()
    db.refresh(model)
    ai_engine.refresh_config()
    logger.info(f"AI model config created: {req.name}")
    return {"code": 200, "message": "AI模型配置已创建", "data": {"id": model.id}}


@router.put("/ai-models/{model_id}")
def update_ai_model(model_id: int, req: AIModelRequest, db: Session = Depends(get_db)):
    model = db.query(AIModelConfig).filter(AIModelConfig.id == model_id).first()
    if not model:
        raise HTTPException(status_code=404, detail="AI模型配置不存在")

    if req.is_default:
        db.query(AIModelConfig).filter(AIModelConfig.is_default == True, AIModelConfig.id != model_id).update({"is_default": False})

    model.name = req.name
    model.provider = req.provider
    model.api_base = req.api_base
    if req.api_key:
        model.api_key = req.api_key
    model.model_name = req.model_name
    model.temperature = req.temperature
    model.max_tokens = req.max_tokens
    model.timeout = req.timeout
    model.is_enabled = req.is_enabled
    model.is_default = req.is_default
    model.updated_at = datetime.utcnow()
    db.commit()
    ai_engine.refresh_config()
    logger.info(f"AI model config updated: {req.name}")
    return {"code": 200, "message": "AI模型配置已更新"}


@router.delete("/ai-models/{model_id}")
def delete_ai_model(model_id: int, db: Session = Depends(get_db)):
    model = db.query(AIModelConfig).filter(AIModelConfig.id == model_id).first()
    if not model:
        raise HTTPException(status_code=404, detail="AI模型配置不存在")
    db.delete(model)
    db.commit()
    ai_engine.refresh_config()
    logger.info(f"AI model config deleted: id={model_id}")
    return {"code": 200, "message": "AI模型配置已删除"}


@router.post("/ai-models/{model_id}/test")
def test_ai_model(model_id: int, db: Session = Depends(get_db)):
    model = db.query(AIModelConfig).filter(AIModelConfig.id == model_id).first()
    if not model:
        raise HTTPException(status_code=404, detail="AI模型配置不存在")

    try:
        import httpx
        client = httpx.Client(
            base_url=model.api_base,
            timeout=float(model.timeout),
            headers={
                "Authorization": f"Bearer {model.api_key}",
                "Content-Type": "application/json",
            },
        )
        payload = {
            "model": model.model_name,
            "messages": [
                {"role": "user", "content": "Hello, respond with 'OK' only."},
            ],
            "max_tokens": 10,
        }
        response = client.post("/chat/completions", json=payload)
        if response.status_code == 200:
            return {"code": 200, "message": "连接测试成功", "data": {"status": "ok"}}
        else:
            return {"code": 400, "message": f"API返回错误: {response.status_code}", "data": {"status": "error", "detail": response.text[:200]}}
    except Exception as e:
        return {"code": 400, "message": f"连接测试失败: {str(e)}", "data": {"status": "error"}}


# ============================================================
# Info Gathering Keys (FOFA / Hunter / Shodan / etc.)
# ============================================================

SUPPORTED_PLATFORMS = [
    {"key": "fofa", "name": "FOFA", "icon": "🌐", "description": "网络空间测绘平台"},
    {"key": "hunter", "name": "Hunter", "icon": "🔍", "description": "鹰图平台"},
    {"key": "shodan", "name": "Shodan", "icon": "🛰️", "description": "全球设备搜索引擎"},
    {"key": "quake", "name": "Quake", "icon": "📡", "description": "360网络空间测绘"},
    {"key": "zoomeye", "name": "ZoomEye", "icon": "👁️", "description": "知道创宇网络空间搜索引擎"},
    {"key": "censys", "name": "Censys", "icon": "🔬", "description": "互联网资产发现平台"},
    {"key": "virustotal", "name": "VirusTotal", "icon": "🛡️", "description": "恶意软件分析平台"},
    {"key": "securitytrails", "name": "SecurityTrails", "icon": "🗺️", "description": "DNS/域名情报平台"},
    {"key": "alienvault", "name": "AlienVault OTX", "icon": "👽", "description": "威胁情报共享平台"},
    {"key": "binaryedge", "name": "BinaryEdge", "icon": "📊", "description": "互联网扫描数据平台"},
]


@router.get("/info-keys/platforms")
def list_supported_platforms():
    return {"code": 200, "data": SUPPORTED_PLATFORMS}


@router.get("/info-keys")
def list_info_keys(db: Session = Depends(get_db)):
    keys = db.query(InfoGatheringKey).order_by(InfoGatheringKey.created_at.desc()).all()
    return {
        "code": 200,
        "data": [
            {
                "id": k.id,
                "platform": k.platform,
                "api_key": k.api_key[:8] + "****" if k.api_key else "",
                "email": k.email,
                "is_enabled": k.is_enabled,
                "extra_config": k.extra_config,
                "created_at": str(k.created_at) if k.created_at else None,
                "updated_at": str(k.updated_at) if k.updated_at else None,
            }
            for k in keys
        ],
    }


@router.post("/info-keys")
def create_info_key(req: InfoKeyRequest, db: Session = Depends(get_db)):
    existing = db.query(InfoGatheringKey).filter(InfoGatheringKey.platform == req.platform).first()
    if existing:
        existing.api_key = req.api_key
        existing.email = req.email
        existing.is_enabled = req.is_enabled
        existing.extra_config = req.extra_config
        existing.updated_at = datetime.utcnow()
        db.commit()
        return {"code": 200, "message": f"{req.platform} Key已更新"}

    key = InfoGatheringKey(
        platform=req.platform,
        api_key=req.api_key,
        email=req.email,
        is_enabled=req.is_enabled,
        extra_config=req.extra_config,
    )
    db.add(key)
    db.commit()
    db.refresh(key)
    logger.info(f"Info gathering key created: {req.platform}")
    return {"code": 200, "message": f"{req.platform} Key已添加", "data": {"id": key.id}}


@router.put("/info-keys/{key_id}")
def update_info_key(key_id: int, req: InfoKeyRequest, db: Session = Depends(get_db)):
    key = db.query(InfoGatheringKey).filter(InfoGatheringKey.id == key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key配置不存在")

    key.platform = req.platform
    if req.api_key:
        key.api_key = req.api_key
    key.email = req.email
    key.is_enabled = req.is_enabled
    key.extra_config = req.extra_config
    key.updated_at = datetime.utcnow()
    db.commit()
    return {"code": 200, "message": "Key配置已更新"}


@router.delete("/info-keys/{key_id}")
def delete_info_key(key_id: int, db: Session = Depends(get_db)):
    key = db.query(InfoGatheringKey).filter(InfoGatheringKey.id == key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key配置不存在")
    db.delete(key)
    db.commit()
    return {"code": 200, "message": "Key配置已删除"}


# ============================================================
# System Settings
# ============================================================

@router.get("/system")
def list_system_settings(db: Session = Depends(get_db)):
    settings = db.query(SystemSettings).all()
    return {
        "code": 200,
        "data": [
            {"key": s.key, "value": s.value, "description": s.description, "updated_at": str(s.updated_at) if s.updated_at else None}
            for s in settings
        ],
    }


@router.post("/system")
def set_system_setting(req: SystemSettingRequest, db: Session = Depends(get_db)):
    setting = db.query(SystemSettings).filter(SystemSettings.key == req.key).first()
    if setting:
        setting.value = req.value
        setting.description = req.description
        setting.updated_at = datetime.utcnow()
    else:
        setting = SystemSettings(key=req.key, value=req.value, description=req.description)
        db.add(setting)
    db.commit()
    return {"code": 200, "message": "系统设置已保存"}


@router.get("/system/{key}")
def get_system_setting(key: str, db: Session = Depends(get_db)):
    setting = db.query(SystemSettings).filter(SystemSettings.key == key).first()
    if not setting:
        return {"code": 200, "data": {"key": key, "value": ""}}
    return {"code": 200, "data": {"key": setting.key, "value": setting.value, "description": setting.description}}
