# -*- coding: utf-8 -*-
"""扫描器加载、CVE 知识库、报告生成器完整性测试。"""

from app.scanner import loader
from app.knowledge.cve_db import CVEDatabase
from app.ai.report_generator import RISK_CONFIG, build_svg_risk_chart, build_svg_score_gauge, generate_report_id


class TestScannerLoader:
    def test_modules_registered(self):
        scanners = loader.get_all_scanners()
        # README 承诺 27+ 检测模块
        assert len(scanners) >= 27

    def test_categories_match_config(self):
        from app.config import SCAN_CATEGORIES
        cats = loader.get_registered_categories()
        for category in SCAN_CATEGORIES:
            assert category in cats, f"missing category: {category}"

    def test_scanner_classes_have_metadata(self):
        scanners = loader.get_all_scanners()
        for key, cls in scanners.items():
            assert hasattr(cls, "category"), key
            assert hasattr(cls, "module"), key

    def test_get_scanner_by_module(self):
        assert loader.get_scanner_by_module("log4j2_jndi") is not None
        assert loader.get_scanner_by_module("nonexistent_module_xyz") is None


class TestCVEDatabase:
    def setup_method(self):
        self.db = CVEDatabase()

    def test_list_not_empty(self):
        assert len(self.db.list_all()) >= 20

    def test_search_log4shell(self):
        results = self.db.search("44228")
        assert len(results) >= 1

    def test_get_by_cve_id(self):
        record = self.db.get_by_cve_id("CVE-2021-44228")
        assert record is not None


class TestReportGenerator:
    def test_risk_config_complete(self):
        for level in ("critical", "high", "medium", "low", "info"):
            assert level in RISK_CONFIG
            assert "label" in RISK_CONFIG[level]
            assert "color" in RISK_CONFIG[level]

    def test_svg_chart_generation(self):
        svg = build_svg_risk_chart({"critical": 2, "high": 3, "medium": 1})
        assert svg.startswith("<svg")
        assert "#dc2626" in svg

    def test_score_gauge(self):
        svg = build_svg_score_gauge(8.5)
        assert svg.startswith("<svg")
        assert "8.5" in svg

    def test_report_id_format(self):
        rid = generate_report_id()
        assert rid.startswith("RPT-")
        assert len(rid) == 12
