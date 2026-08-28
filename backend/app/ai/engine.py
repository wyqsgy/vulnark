"""
AI Analysis Engine v2.1 — OpenAI-compatible multi-provider LLM client.

- DB-backed model config bridging (env vars as fallback, hot reload)
- 统一走 aicompat 兼容层：推理模型参数兼容 / 健壮 JSON 解析
- call_ai_stream: SSE 流式调用（用于 AI 报告流式生成）
"""
import json
import threading
import time
from typing import AsyncGenerator, Dict, List, Optional

from aicompat import (  # noqa: F401  (build_llm_kwargs re-export)
    RETRYABLE_STATUS,
    aretry_stream,
    build_llm_kwargs,
    parse_json_response,
    retry,
)

from app.config import AI_CONFIG
from app.utils.logger import get_logger

logger = get_logger("ai_engine")


class AIStatusError(Exception):
    """携带 HTTP 状态码的 AI 网关错误，用于判断是否可重试。"""

    def __init__(self, status: int, detail: str = ""):
        super().__init__(f"API error: {status} {detail}")
        self.status = status


class AIAnalysisEngine:
    def __init__(self):
        self._lock = threading.Lock()
        self.config: Dict = dict(AI_CONFIG)
        self.http_client = None
        self._init_client()

    # ------------------------------------------------------------------
    # 配置解析：DB 默认模型配置 -> 环境变量兜底
    # ------------------------------------------------------------------
    def refresh_config(self) -> Dict:
        """重新加载生效配置。优先使用设置页保存的默认 AI 模型（DB），
        其次回退到环境变量 AI_* 配置。启动时与设置变更后调用。"""
        with self._lock:
            db_cfg = self._load_db_config()
            if db_cfg:
                self.config = db_cfg
                logger.info(f"AI config loaded from DB: {db_cfg['model']} @ {db_cfg['api_base']}")
            else:
                self.config = dict(AI_CONFIG)
                logger.info("AI config loaded from environment defaults")
            self._init_client()
            return {k: v for k, v in self.config.items() if k != "api_key"}

    def _load_db_config(self) -> Optional[Dict]:
        """从数据库读取默认启用的 AI 模型配置；失败时返回 None。"""
        try:
            from app.database import SessionLocal
            from app.models.settings import AIModelConfig

            db = SessionLocal()
            try:
                model = (
                    db.query(AIModelConfig)
                    .filter(AIModelConfig.is_enabled == True, AIModelConfig.is_default == True)  # noqa: E712
                    .first()
                )
                if model is None:
                    model = (
                        db.query(AIModelConfig)
                        .filter(AIModelConfig.is_enabled == True)  # noqa: E712
                        .first()
                    )
                if model is None or not (model.api_key or "").strip():
                    return None
                return {
                    "enabled": True,
                    "provider": model.provider,
                    "api_key": model.api_key,
                    "api_base": (model.api_base or "").rstrip("/"),
                    "model": model.model_name,
                    "temperature": float(model.temperature or 0.1),
                    "max_tokens": int(model.max_tokens or 1024),
                    "timeout": int(model.timeout or 60),
                }
            finally:
                db.close()
        except Exception as e:
            logger.debug(f"DB AI config unavailable ({e}), falling back to env")
            return None

    def _init_client(self):
        self.http_client = None
        if not self.config.get("enabled") or not self.config.get("api_key"):
            return
        if not self.config.get("api_base"):
            return
        try:
            import httpx

            self.http_client = httpx.Client(
                base_url=self.config["api_base"],
                timeout=self.config["timeout"],
                headers={
                    "Authorization": f"Bearer {self.config['api_key']}",
                    "Content-Type": "application/json",
                },
            )
        except Exception as e:
            logger.error(f"AI client init failed: {e}")

    def _is_available(self) -> bool:
        return (
            self.config.get("enabled")
            and bool(self.config.get("api_key"))
            and self.http_client is not None
        )

    # ------------------------------------------------------------------
    # LLM 调用
    # ------------------------------------------------------------------
    def call_ai(self, prompt: str, task_type: str) -> Dict:
        """调用 LLM 并解析 JSON 响应（线程安全）。

        重试统一由 aicompat.retry 承担：429/5xx/超时按指数退避重试，
        4xx 参数错误不重试。失败时返回 {"error": ...} 而非抛出。
        """
        if not self._is_available():
            return {"error": "AI not configured", "status": "fallback_mode"}

        kwargs = build_llm_kwargs(
            self.config["model"],
            temperature=float(self.config.get("temperature", 0.1)),
            max_tokens=int(self.config.get("max_tokens", 1024)),
        )
        kwargs["messages"] = [
            {"role": "system", "content": "你是一个专业的网络安全分析AI，只返回JSON格式数据。"},
            {"role": "user", "content": prompt},
        ]

        def _attempt():
            response = self.http_client.post("/chat/completions", json=kwargs)
            if response.status_code == 200:
                result = response.json()
                content = result["choices"][0]["message"]["content"]
                return self._parse_json_response(content)
            raise AIStatusError(response.status_code, response.text[:200])

        def _can_retry(e: Exception) -> bool:
            if isinstance(e, AIStatusError):
                return e.status in RETRYABLE_STATUS
            return True  # 网络类异常默认可重试

        try:
            return retry(_attempt, retries=3, base_delay=1.5, retry_on=_can_retry)
        except AIStatusError as e:
            logger.error(f"AI API error: {e}")
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"AI call failed: {e}")
            return {"error": str(e)}

    # 兼容旧调用（packet_verifier 曾直接访问私有方法）
    def _call_ai(self, prompt: str, task_type: str) -> Dict:
        return self.call_ai(prompt, task_type)

    @staticmethod
    def _parse_json_response(content: str) -> Dict:
        """健壮的 JSON 解析（委托给 aicompat 统一实现）。"""
        return parse_json_response(content or "")

    async def call_ai_stream(self, prompt: str, task_type: str) -> AsyncGenerator[dict, None]:
        """流式调用 LLM，逐 token 产出 {"type": "token"|"done"|"error", ...}。

        重试统一由 aicompat.aretry_stream 承担：仅在产出任何 token 之前
        重试（429/5xx/网络错误），产出后异常直接抛出并转为 error 事件。
        未配置 AI 时直接产出错误事件。
        """
        if not self._is_available():
            yield {"type": "error", "error": "AI not configured", "status": "fallback_mode"}
            return

        import httpx

        kwargs = build_llm_kwargs(
            self.config["model"],
            temperature=float(self.config.get("temperature", 0.1)),
            max_tokens=max(int(self.config.get("max_tokens", 1024)), 4096),
            stream=True,
        )
        kwargs["messages"] = [
            {"role": "system", "content": "你是一个专业的网络安全分析AI。"},
            {"role": "user", "content": prompt},
        ]

        def _can_retry(e: Exception) -> bool:
            if isinstance(e, AIStatusError):
                return e.status in RETRYABLE_STATUS
            return isinstance(e, httpx.HTTPError)

        try:
            async for event in aretry_stream(
                lambda: self._stream_once(kwargs),
                retries=3,
                base_delay=1.0,
                retry_on=_can_retry,
            ):
                yield event
        except Exception as e:
            logger.error(f"AI stream failed: {e}")
            yield {"type": "error", "error": str(e)}

    async def _stream_once(self, kwargs: Dict) -> AsyncGenerator[dict, None]:
        """单次流式尝试。产出任何 token 前的失败以异常抛出（供重试判定）。"""
        import httpx

        client = httpx.AsyncClient(
            base_url=self.config["api_base"],
            timeout=self.config["timeout"],
            headers={"Authorization": f"Bearer {self.config['api_key']}"},
        )
        produced = False
        try:
            async with client.stream("POST", "/chat/completions", json=kwargs) as response:
                if response.status_code != 200:
                    body = (await response.aread()).decode(errors="replace")[:300]
                    raise AIStatusError(response.status_code, body)
                async for line in response.aiter_lines():
                    if not line.startswith("data:"):
                        continue
                    payload = line[5:].strip()
                    if payload == "[DONE]":
                        break
                    try:
                        chunk = json.loads(payload)
                        delta = chunk["choices"][0].get("delta") or {}
                        content = delta.get("content")
                    except (json.JSONDecodeError, KeyError, IndexError):
                        continue
                    if content:
                        produced = True
                        yield {"type": "token", "content": content}
            if not produced:
                # 空流视为可重试的网关错误
                raise AIStatusError(502, "stream produced no content")
            yield {"type": "done"}
        finally:
            await client.aclose()

    # ------------------------------------------------------------------
    # 分析能力（未配置 AI 时优雅降级）
    # ------------------------------------------------------------------
    def analyze_fingerprint(self, fingerprint_data: Dict) -> Dict:
        if not self._is_available():
            return self._fallback_fingerprint(fingerprint_data)
        prompt = f"""你是一个资深安全专家。根据以下目标指纹信息，分析其技术栈并推荐最适合的漏洞检测模块。
指纹数据: {json.dumps(fingerprint_data, ensure_ascii=False, indent=2)}
请返回JSON格式:
{{
    "tech_stack": ["识别到的技术栈"],
    "recommended_modules": ["推荐的检测模块"],
    "risk_assessment": "风险评估",
    "attack_surface": "攻击面分析",
    "priority_targets": ["优先检测目标"]
}}"""
        return self.call_ai(prompt, "fingerprint_analysis")

    def analyze_vulnerability(self, vuln_data: Dict) -> Dict:
        if not self._is_available():
            return self._fallback_vuln_analysis(vuln_data)
        prompt = f"""你是一个资深安全专家。对以下漏洞进行深度分析。
漏洞数据: {json.dumps(vuln_data, ensure_ascii=False, indent=2)}
请返回JSON格式:
{{
    "confidence": 0-100的置信度评分,
    "is_false_positive": true/false,
    "exploitability": "可利用性评估",
    "impact": "影响范围评估",
    "remediation": "修复建议",
    "cvss_score": "CVSS评分",
    "attack_chain": "可能的攻击链",
    "evidence_quality": "证据质量评估"
}}"""
        return self.call_ai(prompt, "vuln_analysis")

    def adapt_payload(self, payload: str, context: Dict) -> Dict:
        if not self._is_available():
            return {"adapted_payloads": [payload]}
        prompt = f"""你是一个WAF绕过专家。根据以下上下文，将Payload变形以绕过WAF/过滤。
原始Payload: {payload}
上下文: {json.dumps(context, ensure_ascii=False)}
请返回JSON格式:
{{
    "adapted_payloads": ["变形后的Payload列表"],
    "techniques_used": ["使用的技术"],
    "explanation": "解释"
}}"""
        return self.call_ai(prompt, "payload_adaptation")

    def detect_false_positive(self, vuln_data: Dict, response_data: Dict) -> Dict:
        if not self._is_available():
            return {"is_false_positive": False, "confidence": 50}
        prompt = f"""你是一个漏洞验证专家。判断以下漏洞发现是否为误报。
漏洞信息: {json.dumps(vuln_data, ensure_ascii=False, indent=2)}
响应数据: {json.dumps(response_data, ensure_ascii=False, indent=2)[:1000]}
请返回JSON格式:
{{
    "is_false_positive": true/false,
    "confidence": 0-100,
    "reasoning": "判断依据",
    "suggestion": "建议"
}}"""
        return self.call_ai(prompt, "false_positive_detection")

    def generate_remediation(self, vuln_list: List[Dict]) -> Dict:
        if not self._is_available():
            return self._fallback_remediation(vuln_list)
        prompt = f"""你是一个安全修复专家。为以下漏洞列表生成详细的修复方案。
漏洞列表: {json.dumps(vuln_list, ensure_ascii=False, indent=2)[:2000]}
请返回JSON格式:
{{
    "priority_fix": ["按优先级排序的修复项"],
    "quick_wins": ["快速可实施的修复"],
    "long_term": ["长期安全加固建议"],
    "configuration_changes": ["配置变更建议"],
    "code_changes": ["代码层面修复建议"]
}}"""
        return self.call_ai(prompt, "remediation")

    def classify_target(self, url: str, response_data: Dict) -> Dict:
        if not self._is_available():
            return self._fallback_classify(response_data)
        prompt = f"""分析以下URL和响应数据，判断目标类型和可能存在的漏洞。
URL: {url}
响应状态码: {response_data.get('status_code', 'N/A')}
响应头: {json.dumps(dict(response_data.get('headers', {})), ensure_ascii=False)[:500]}
响应体(前500字符): {str(response_data.get('text', ''))[:500]}
请返回JSON格式:
{{
    "target_type": "目标类型(web/api/database/middleware/etc)",
    "technology": "技术栈",
    "potential_vulns": ["可能存在的漏洞类型"],
    "recommended_scans": ["推荐的扫描模块"],
    "risk_level": "预估风险等级"
}}"""
        return self.call_ai(prompt, "target_classification")

    # ------------------------------------------------------------------
    # 降级响应
    # ------------------------------------------------------------------
    def _fallback_fingerprint(self, data: Dict) -> Dict:
        return {
            "tech_stack": [fw["name"] for fw in data.get("framework", [])],
            "recommended_modules": [],
            "risk_assessment": "需要AI配置以获取深度分析",
            "attack_surface": "基础指纹识别已完成",
            "status": "fallback_mode",
        }

    def _fallback_vuln_analysis(self, data: Dict) -> Dict:
        return {
            "confidence": 70,
            "is_false_positive": False,
            "exploitability": "需要人工确认",
            "status": "fallback_mode",
        }

    def _fallback_remediation(self, vulns: List[Dict]) -> Dict:
        return {
            "priority_fix": [f"修复 {v.get('name', 'Unknown')}" for v in vulns[:5]],
            "quick_wins": ["更新软件版本", "启用安全头", "限制访问权限"],
            "long_term": ["实施WAF", "定期安全审计", "代码安全培训"],
            "status": "fallback_mode",
        }

    def _fallback_classify(self, data: Dict) -> Dict:
        return {
            "target_type": "unknown",
            "technology": "unknown",
            "status": "fallback_mode",
        }


# 全局单例（配置延迟加载：启动后由 main.py 调用 refresh_config 从 DB 读取）
ai_engine = AIAnalysisEngine()
