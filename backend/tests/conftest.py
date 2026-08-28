# -*- coding: utf-8 -*-
"""WyqYan v2.0.0 测试套件：AI 引擎、配置、扫描器加载、报告生成。"""

import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))
