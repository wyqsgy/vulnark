# -*- coding: utf-8 -*-
"""v2.1 鉴权中间件、扫描目标白名单、aicompat 接入测试。"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

import app.config as config
from app.core.target_guard import validate_scan_target
from app.main import app


class TestTargetGuard:
    def test_no_allowlist_allows_all(self):
        assert validate_scan_target("https://anything.example.com", []) is True
        assert validate_scan_target("https://x.com", None) is True

    def test_exact_ip(self):
        allow = ["10.0.0.5"]
        assert validate_scan_target("10.0.0.5", allow) is True
        assert validate_scan_target("http://10.0.0.5:8080/admin", allow) is True
        assert validate_scan_target("10.0.0.6", allow) is False

    def test_cidr(self):
        allow = ["192.168.1.0/24"]
        assert validate_scan_target("192.168.1.100", allow) is True
        assert validate_scan_target("192.168.2.100", allow) is False

    def test_domain_and_subdomain(self):
        allow = ["example.com"]
        assert validate_scan_target("example.com", allow) is True
        assert validate_scan_target("http://api.example.com/x", allow) is True
        assert validate_scan_target("evil-example.com", allow) is False

    def test_wildcard_domain(self):
        allow = ["*.staging.example.com"]
        assert validate_scan_target("app.staging.example.com", allow) is True
        assert validate_scan_target("staging.example.com", allow) is False

    def test_url_with_port_and_path(self):
        allow = ["10.0.0.0/8"]
        assert validate_scan_target("http://10.1.2.3:7001/console", allow) is True


@pytest.fixture(autouse=True)
def _reset_state(monkeypatch):
    # 限流/鉴权均为模块级状态，测试前重置
    monkeypatch.setattr(config, "API_TOKEN", "")
    monkeypatch.setattr(config, "ALLOWED_SCAN_TARGETS", [])
    yield


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


class TestAuthMiddleware:
    async def test_health_always_open(self, client):
        assert (await client.get("/api/health")).status_code == 200

    async def test_401_when_enabled(self, client, monkeypatch):
        monkeypatch.setattr(config, "API_TOKEN", "t-123")
        assert (await client.get("/api/tasks")).status_code == 401
        assert (await client.get("/api/tasks", headers={"X-API-Token": "t-123"})).status_code == 200
        assert (await client.get("/api/tasks", headers={"Authorization": "Bearer t-123"})).status_code == 200
        assert (await client.get("/api/tasks", headers={"X-API-Token": "bad"})).status_code == 401


class TestScanTargetEnforced:
    async def test_create_task_blocked_outside_scope(self, client, monkeypatch):
        monkeypatch.setattr(config, "ALLOWED_SCAN_TARGETS", ["10.0.0.0/8"])
        resp = await client.post("/api/tasks", json={"target": "https://evil.example.com"})
        assert resp.status_code == 403
        assert "授权扫描范围" in resp.json()["detail"]
