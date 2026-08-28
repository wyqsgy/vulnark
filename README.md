# vulnark - AI驱动的框架/中间件漏洞集合自动化验证平台

<p align="center">
  <strong>🛡️ 集成化 · 自动化 · AI驱动</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue?logo=python" />
  <img src="https://img.shields.io/badge/fastapi-0.116-green?logo=fastapi" />
  <img src="https://img.shields.io/badge/react-18-blue?logo=react" />
  <img src="https://img.shields.io/badge/version-2.0.0-purple" />
  <img src="https://img.shields.io/badge/modules-27+-red" />
  <img src="https://img.shields.io/badge/license-MIT-blue" />
  <img src="https://img.shields.io/badge/ai-powered-purple" />
</p>

## 🆕 v2.0.0 更新日志

- **设置页模型配置真正生效**：修复「设置页保存的默认 AI 模型（DB 配置）从未被 AI 引擎读取」的断连问题——引擎现在优先使用 DB 默认模型配置，环境变量 `AI_*` 作为兜底，配置变更后热重载，无需重启
- **修复 AI 引擎静默失效**：依赖清单缺失 `httpx`，导致 AI 客户端初始化 `ImportError` 被吞掉、AI 功能开箱即坏；现已补入
- **推理模型兼容**：o1/o3/o4/GPT-5 系模型自动切换 `max_completion_tokens` 并忽略 `temperature`，不再 400
- **LLM 调用重试**：429/5xx/超时按指数退避自动重试 3 次
- **JSON 解析加固**：模型输出带前后缀文本、代码块包裹时均能正确解析
- **依赖全面升级并修复真实 CVE**：`python-multipart 0.0.6 → 0.0.20`（CVE-2024-24762 ReDoS）、`aiohttp 3.9.1 → 3.12`、`fastapi 0.104 → 0.116` 等 13 项
- **Docker 数据持久化修复**：compose 卷声明不匹配（`wyqy-data` 未声明）导致数据库数据随容器重建丢失；同时为后端增加健康检查、AI 配置透传
- **CVE 知识库扩容**：新增 ActiveMQ (CVE-2023-46604)、Tomcat (CVE-2023-28708 / CVE-2024-50379)、Spring SpEL DoS (CVE-2023-20861)
- **新增测试套件**：26 个用例覆盖 AI 引擎（JSON 解析/参数兼容/配置解析/降级模式）、扫描器注册完整性、CVE 库、报告生成器

## 简介

wyqY 是一个专注于**主流框架和中间件漏洞**的自动化验证平台，集成 AI 智能分析能力，可自动发现、验证和报告安全漏洞。覆盖 18 个组件、27+ 检测模块，内置 CVE 知识库关联，支持 WebSocket 实时进度推送和多格式报告导出。

## 支持的漏洞模块

| 组件 | 漏洞类型 | CVE编号 | 风险等级 |
|------|---------|---------|---------|
| **Spring Framework** | Spring4Shell RCE | CVE-2022-22965 | 严重 |
| **Spring Framework** | SpEL 注入 | CVE-2022-22963 | 严重 |
| **Spring Framework** | Actuator 未授权访问 | - | 高危 |
| **Spring Framework** | H2 Database RCE | CVE-2022-22978 | 严重 |
| **Spring Cloud Gateway** | SpEL RCE | CVE-2022-22947 | 严重 |
| **Spring Cloud Function** | 路由表达式RCE | CVE-2022-22963 | 严重 |
| **Spring Cloud Data Flow** | Dashboard未授权 | CVE-2022-22947 | 高危 |
| **Apache Shiro** | RememberMe 反序列化 | CVE-2016-4437 | 严重 |
| **Apache Shiro** | 权限绕过 | CVE-2020-1957 | 高危 |
| **Log4j2** | JNDI 注入 (Log4Shell) | CVE-2021-44228 | 严重 |
| **Fastjson** | 反序列化 RCE | CVE-2017-18349 | 严重 |
| **Nacos** | 认证绕过 | CVE-2021-29441 | 高危 |
| **Nacos** | Derby SQL注入 RCE | CVE-2021-29442 | 严重 |
| **Druid** | 监控面板未授权访问 | - | 中危 |
| **Tomcat** | Manager 未授权/弱口令 | - | 高危 |
| **Struts2** | OGNL 注入系列 | CVE-2017-5638 | 严重 |
| **ThinkPHP** | 5.x/6.x RCE 系列 | CVE-2018-20062 | 严重 |
| **Oracle WebLogic** | 反序列化/SSRF/未授权RCE | CVE-2020-14882 | 严重 |
| **Redis** | 未授权访问/CONFIG执行 | - | 严重 |
| **Atlassian Confluence** | OGNL注入RCE | CVE-2022-26134 | 严重 |
| **F5 BIG-IP** | iControl REST RCE | CVE-2022-1388 | 严重 |
| **Jenkins** | 未授权访问/Script Console | CVE-2018-1000861 | 严重 |
| **Apache Flink** | 未授权访问/Jar上传RCE | CVE-2020-17518 | 严重 |
| **XXL-JOB** | 执行器API未授权RCE | CVE-2022-43385 | 严重 |
| **Nginx** | 路径穿越/CRLF注入/目录遍历 | CVE-2021-23017 | 高危 |
| **Elasticsearch** | 未授权访问/数据泄露 | - | 严重 |

## 核心特性

- **插件化架构**: 每个漏洞模块独立封装，基于装饰器自动注册，易于扩展
- **AI误报过滤**: 基于特征工程 + ML模型智能过滤误报，降低噪音
- **CVE知识库**: 内置20+高危CVE记录，自动关联扫描结果
- **WebSocket实时推送**: 扫描进度、漏洞发现实时推送到前端
- **多格式导出**: 支持JSON/CSV格式漏洞报告导出
- **全局异常处理**: 统一异常捕获 + 结构化请求日志
- **异步扫描**: 多线程并发扫描引擎，支持任务启动/停止管理
- **现代化前端**: React + TailwindCSS + Recharts 仪表板

## 技术架构

```
┌──────────────────────────────────────────────────────────────┐
│                     Frontend (React + TailwindCSS)           │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐│
│  │Dashboard │ │TaskList  │ │VulnList  │ │WebSocket Listener││
│  └──────────┘ └──────────┘ └──────────┘ └──────────────────┘│
└──────────────────────────────────────────────────────────────┘
                             │ REST API + WebSocket
┌──────────────────────────────────────────────────────────────┐
│                     Backend (FastAPI + SQLAlchemy)            │
│  ┌──────────────────────────────────────────────────────────┐│
│  │  Middleware: RequestLogger + GlobalExceptionHandler       ││
│  └──────────────────────────────────────────────────────────┘│
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐   │
│  │Tasks API │ │Scans API │ │Export API│ │CVE Knowledge │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────┘   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Scan Engine (ThreadPoolExecutor + WebSocket Broadcast)│   │
│  │  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐         │   │
│  │  │ Spring │ │ Shiro  │ │Log4j2  │ │  ...   │ x27+    │   │
│  │  │Module  │ │Module  │ │Module  │ │        │ modules │   │
│  │  └────────┘ └────────┘ └────────┘ └────────┘         │   │
│  └──────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  AI Module: FeatureExtractor + Classifier + Reporter  │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
                             │
┌──────────────────────────────────────────────────────────────┐
│                     Storage                                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────────────────────────┐ │
│  │  SQLite  │ │CVE DB    │ │  Reports (HTML/JSON/CSV)     │ │
│  └──────────┘ └──────────┘ └──────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

## 快速开始

### 方式一：Docker 一键部署

```bash
docker-compose up -d
```

访问 http://localhost:3080

### 方式二：本地开发

**后端：**
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

**前端：**
```bash
cd frontend
npm install
npm run dev
```

访问 http://localhost:5173

### API文档

后端启动后访问 http://localhost:8000/docs

### 主要API端点

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/tasks` | POST | 创建扫描任务 |
| `/api/tasks` | GET | 获取任务列表 |
| `/api/tasks/{id}` | GET | 获取任务详情 |
| `/api/tasks/{id}/stop` | POST | 停止扫描任务 |
| `/api/scans/vulnerabilities` | GET | 获取漏洞列表 |
| `/api/export/vulnerabilities` | GET | 导出漏洞(JSON/CSV) |
| `/api/export/report/{task_id}` | GET | 导出任务报告 |
| `/api/cve/list` | GET | CVE知识库列表 |
| `/api/cve/search` | GET | CVE搜索 |
| `/api/cve/{cve_id}` | GET | CVE详情 |
| `/api/reports/generate` | POST | 生成AI报告 |
| `/ws/tasks/{task_id}` | WS | 任务实时进度 |

## 项目结构

```
wyqy/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI入口
│   │   ├── config.py            # 配置管理
│   │   ├── database.py          # 数据库连接
│   │   ├── api/                 # API路由
│   │   │   ├── tasks.py         # 任务管理API
│   │   │   ├── scans.py         # 扫描结果API
│   │   │   ├── reports.py       # 报告API
│   │   │   ├── export.py        # 导出API (JSON/CSV)
│   │   │   ├── cve.py           # CVE知识库API
│   │   │   └── ws.py            # WebSocket端点
│   │   ├── models/              # 数据模型
│   │   ├── scanner/             # 扫描引擎
│   │   │   ├── base.py          # 扫描器基类
│   │   │   ├── loader.py        # 插件化加载
│   │   │   ├── engine.py        # 异步扫描引擎 + WS广播
│   │   │   └── modules/         # 27+漏洞检测模块
│   │   ├── ai/                  # AI分析模块
│   │   │   ├── classifier.py    # 误报过滤器
│   │   │   ├── feature_extractor.py
│   │   │   └── report_generator.py
│   │   ├── knowledge/           # CVE知识库
│   │   │   └── cve_db.py        # 内置CVE数据库
│   │   ├── middleware/          # 中间件
│   │   │   ├── exceptions.py    # 全局异常处理
│   │   │   └── request_logger.py # 请求日志
│   │   └── utils/               # 工具类
│   └── requirements.txt
├── frontend/
│   └── src/
│       ├── api/                 # API调用
│       ├── components/          # 组件
│       └── pages/               # 页面
├── docker-compose.yml
├── .github/workflows/ci.yml    # CI/CD
└── .trae/skills/github-manager/ # GitHub管理Skill
```

## 技术栈

- **后端**: Python 3.10+, FastAPI, SQLAlchemy, SQLite, WebSockets
- **前端**: React 18, TailwindCSS, Recharts, Vite, React Router
- **AI**: 特征工程 + 规则引擎 + ML分类器
- **部署**: Docker, Nginx, GitHub Actions CI/CD

## 免责声明

本工具仅用于**合法的安全测试和教育研究**目的。使用者需确保已获得目标系统的授权。任何未经授权的非法使用，责任由使用者自行承担。
