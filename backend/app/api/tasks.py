from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.core.target_guard import validate_scan_target
from app.database import get_db
from app.models.task import ScanTask, TaskStatus
from app.scanner.engine import start_scan, stop_scan
from app.scanner.loader import get_registered_categories
from app.utils.helper import gen_task_id

router = APIRouter(prefix="/api/tasks", tags=["tasks"])


class CreateTaskRequest(BaseModel):
    target: str
    categories: list[str] = ["all"]
    scan_type: str = "quick"
    modules: list[str] | None = None


class TaskResponse(BaseModel):
    task_id: str
    target: str
    categories: list
    status: str
    progress: int
    total_checks: int
    vuln_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    created_at: str
    finished_at: str | None

    class Config:
        from_attributes = True


@router.post("")
def create_task(req: CreateTaskRequest, db: Session = Depends(get_db)):
    # 授权范围校验：设置 ALLOWED_SCAN_TARGETS 后仅放行白名单内目标
    if not validate_scan_target(req.target):
        raise HTTPException(
            status_code=403,
            detail=f"目标 {req.target} 不在授权扫描范围内（ALLOWED_SCAN_TARGETS）",
        )

    task_id = gen_task_id()

    categories = req.categories
    if req.modules:
        categories = req.modules
    elif req.scan_type == "recon":
        categories = ["recon"]
    elif req.scan_type == "stealth":
        categories = ["all"]

    task = ScanTask(
        task_id=task_id,
        target=req.target,
        categories=categories,
        status=TaskStatus.PENDING,
    )
    db.add(task)
    db.commit()
    db.refresh(task)

    start_scan(task_id, req.target, categories, scan_mode=req.scan_type)

    return {
        "code": 200,
        "message": "Scan task created",
        "data": {"task_id": task_id, "target": req.target, "status": "pending"},
    }


@router.get("")
def list_tasks(skip: int = 0, limit: int = 20, status: str = None, db: Session = Depends(get_db)):
    query = db.query(ScanTask).order_by(ScanTask.created_at.desc())
    if status:
        query = query.filter(ScanTask.status == status)
    total = query.count()
    tasks = query.offset(skip).limit(limit).all()

    task_list = []
    for t in tasks:
        task_list.append({
            "task_id": t.task_id,
            "target": t.target,
            "categories": t.categories or [],
            "status": t.status.value if isinstance(t.status, TaskStatus) else t.status,
            "progress": t.progress,
            "total_checks": t.total_checks,
            "vuln_count": t.vuln_count,
            "critical_count": t.critical_count,
            "high_count": t.high_count,
            "medium_count": t.medium_count,
            "low_count": t.low_count,
            "created_at": str(t.created_at) if t.created_at else None,
            "finished_at": str(t.finished_at) if t.finished_at else None,
        })

    return {"code": 200, "data": {"total": total, "items": task_list}}


@router.get("/categories")
def list_categories():
    cats = get_registered_categories()
    return {"code": 200, "data": cats}


@router.get("/{task_id}")
def get_task(task_id: str, db: Session = Depends(get_db)):
    task = db.query(ScanTask).filter(ScanTask.task_id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    return {
        "code": 200,
        "data": {
            "task_id": task.task_id,
            "target": task.target,
            "categories": task.categories or [],
            "status": task.status.value if isinstance(task.status, TaskStatus) else task.status,
            "progress": task.progress,
            "total_checks": task.total_checks,
            "vuln_count": task.vuln_count,
            "critical_count": task.critical_count,
            "high_count": task.high_count,
            "medium_count": task.medium_count,
            "low_count": task.low_count,
            "fingerprint": task.fingerprint or {},
            "error_msg": task.error_msg or "",
            "created_at": str(task.created_at) if task.created_at else None,
            "finished_at": str(task.finished_at) if task.finished_at else None,
        },
    }


@router.post("/{task_id}/stop")
def stop_task(task_id: str, db: Session = Depends(get_db)):
    task = db.query(ScanTask).filter(ScanTask.task_id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    stop_scan(task_id)
    return {"code": 200, "message": "Stop signal sent"}


@router.delete("/{task_id}")
def delete_task(task_id: str, db: Session = Depends(get_db)):
    task = db.query(ScanTask).filter(ScanTask.task_id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    stop_scan(task_id)
    db.delete(task)
    db.commit()
    return {"code": 200, "message": "Task deleted"}
