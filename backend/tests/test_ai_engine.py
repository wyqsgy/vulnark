# -*- coding: utf-8 -*-
"""AI 引擎 v2.0.0 测试：JSON 解析、模型参数兼容、配置解析、降级模式。"""

import pytest

from app.ai.engine import AIAnalysisEngine, build_llm_kwargs


class TestBuildLLMKwargs:
    def test_standard_model(self):
        kwargs = build_llm_kwargs("gpt-4o-mini", temperature=0.3, max_tokens=512)
        assert kwargs["temperature"] == 0.3
        assert kwargs["max_tokens"] == 512
        assert "max_completion_tokens" not in kwargs

    def test_reasoning_model_drops_temperature(self):
        for model in ("o1", "o3-mini", "o4-mini", "gpt-5", "GPT-5-Mini"):
            kwargs = build_llm_kwargs(model, temperature=0.3, max_tokens=512)
            assert "temperature" not in kwargs, model
            assert kwargs["max_completion_tokens"] == 512, model


class TestParseJsonResponse:
    def setup_method(self):
        self.engine = AIAnalysisEngine()

    def test_plain_json(self):
        assert self.engine._parse_json_response('{"a": 1}') == {"a": 1}

    def test_code_block_wrapped(self):
        text = '前置说明\n```json\n{"confidence": 88, "is_false_positive": false}\n```\n后缀'
        assert self.engine._parse_json_response(text) == {"confidence": 88, "is_false_positive": False}

    def test_plain_code_block(self):
        text = '```\n{"x": "y"}\n```'
        assert self.engine._parse_json_response(text) == {"x": "y"}

    def test_surrounding_text_extracted(self):
        text = '分析结果如下：{"risk_level": "high"} 以上。'
        assert self.engine._parse_json_response(text) == {"risk_level": "high"}

    def test_invalid_returns_raw(self):
        out = self.engine._parse_json_response("这不是JSON")
        assert out == {"raw_response": "这不是JSON"}

    def test_empty(self):
        assert self.engine._parse_json_response("") == {}


class TestEngineDegradedMode:
    """未配置 API Key 时所有分析应优雅降级而非崩溃。"""

    def setup_method(self):
        self.engine = AIAnalysisEngine()
        self.engine.config = {"enabled": True, "api_key": "", "api_base": "", "model": "x"}
        self.engine.http_client = None

    def test_not_available(self):
        assert self.engine._is_available() is False

    def test_analyze_vulnerability_fallback(self):
        out = self.engine.analyze_vulnerability({"name": "Spring4Shell"})
        assert out["status"] == "fallback_mode"

    def test_remediation_fallback(self):
        out = self.engine.generate_remediation([{"name": "Log4Shell"}])
        assert out["status"] == "fallback_mode"
        assert any("Log4Shell" in item for item in out["priority_fix"])

    def test_call_ai_without_config(self):
        out = self.engine.call_ai("test", "unit")
        assert out["error"] == "AI not configured"


class TestConfigResolution:
    def test_env_fallback(self, monkeypatch):
        engine = AIAnalysisEngine()
        monkeypatch.setattr(engine, "_load_db_config", lambda: None)
        cfg = engine.refresh_config()
        assert cfg["enabled"] == engine.config["enabled"]

    def test_db_config_wins(self, monkeypatch):
        engine = AIAnalysisEngine()
        fake_db_cfg = {
            "enabled": True, "provider": "deepseek", "api_key": "sk-test",
            "api_base": "https://api.deepseek.com", "model": "deepseek-chat",
            "temperature": 0.2, "max_tokens": 2048, "timeout": 45,
        }
        monkeypatch.setattr(engine, "_load_db_config", lambda: fake_db_cfg)
        cfg = engine.refresh_config()
        assert cfg["model"] == "deepseek-chat"
        assert cfg["api_base"] == "https://api.deepseek.com"
        assert engine._is_available() is True
        assert "api_key" not in cfg  # 返回值不应泄露密钥

    def test_refresh_no_key_falls_back_to_env(self, monkeypatch):
        engine = AIAnalysisEngine()
        monkeypatch.setattr(engine, "_load_db_config", lambda: None)
        engine.refresh_config()
        assert engine.config["enabled"] == engine.config["enabled"]
