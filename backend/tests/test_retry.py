# -*- coding: utf-8 -*-
"""v2.1 重试收编测试：call_ai 经 aicompat.retry 仅重试可重试错误。"""

import json

import pytest

from app.ai.engine import AIAnalysisEngine


def _engine():
    engine = AIAnalysisEngine()
    engine.config = {
        "enabled": True, "api_key": "sk-x", "api_base": "https://x",
        "model": "gpt-4o", "temperature": 0.1, "max_tokens": 64, "timeout": 5,
    }
    return engine


class _Response:
    def __init__(self, status_code, content=None, text=""):
        self.status_code = status_code
        self.text = text
        self._content = content

    def json(self):
        return {"choices": [{"message": {"content": self._content}}]}


class TestCallAIRetry:
    def test_retries_on_5xx_then_succeeds(self, monkeypatch):
        engine = _engine()
        responses = [
            _Response(500, text="boom"),
            _Response(503, text="down"),
            _Response(200, content=json.dumps({"ok": 1})),
        ]

        class FakeClient:
            def post(self, url, **kw):
                return responses.pop(0)

        engine.http_client = FakeClient()
        monkeypatch.setattr("time.sleep", lambda s: None)
        assert engine.call_ai("p", "t") == {"ok": 1}

    def test_no_retry_on_400(self, monkeypatch):
        engine = _engine()
        calls = {"n": 0}

        class FakeClient:
            def post(self, url, **kw):
                calls["n"] += 1
                return _Response(400, text="bad request")

        engine.http_client = FakeClient()
        monkeypatch.setattr("time.sleep", lambda s: None)
        out = engine.call_ai("p", "t")
        assert "error" in out
        assert calls["n"] == 1  # 4xx 参数错误不重试

    def test_retries_on_network_error(self, monkeypatch):
        engine = _engine()
        calls = {"n": 0}

        class FakeClient:
            def post(self, url, **kw):
                calls["n"] += 1
                if calls["n"] < 2:
                    raise ConnectionError("reset")
                return _Response(200, content=json.dumps({"ok": True}))

        engine.http_client = FakeClient()
        monkeypatch.setattr("time.sleep", lambda s: None)
        assert engine.call_ai("p", "t") == {"ok": True}
        assert calls["n"] == 2
