# SkillScan - Agent Skill Security Analysis Engine

SkillScan 是一个用于自动化扫描和分析 Agent Skills 安全性的威胁分析引擎，基于论文 ["Agent Skills in the Wild: An Empirical Study of Security Vulnerabilities at Scale"](https://arxiv.org/html/2601.10338v1) 中提出的威胁分类体系。

## 功能特性

### 核心能力

- **14种漏洞模式检测**：覆盖4大类安全威胁
- **多语言支持**：支持中文和英文技能文件的检测
- **高性能分析**：三阶段混合检测架构（静态→LLM-Guard→混合分类）
- **双通道采集**：本地目录扫描 + 网络爬取
- **MongoDB存储**：持久化检测结果和配置

### 威胁分类体系

| 类别 | 代码 | 描述 |
|------|------|------|
| **提示注入** | P1 | Instruction Override - 指令覆盖 |
| | P2 | Hidden Instructions - 隐藏指令 |
| | P3 | Exfiltration Commands - 外传命令 |
| | P4 | Behavior Manipulation - 行为操纵 |
| **数据外传** | E1 | External Data Transmission - 外部数据传输 |
| | E2 | Environment Variable Harvesting - 环境变量收集 |
| | E3 | File System Enumeration - 文件系统枚举 |
| | E4 | Context Leakage - 上下文泄露 |
| **权限提升** | PE1 | Excessive Permission Requests - 过度权限请求 |
| | PE2 | Sudo/Root Execution - Sudo/Root执行 |
| | PE3 | Credential Access - 凭证访问 |
| **供应链风险** | SC1 | Unpinned Dependencies - 未锁定依赖 |
| | SC2 | External Script Fetching - 外部脚本获取 |
| | SC3 | Obfuscated Code - 混淆代码 |

## 快速开始

### 环境要求

- Python 3.10+
- MongoDB 6.0+
- Redis 7.0+ (可选，用于任务队列)

### 安装

```bash
# 克隆仓库
git clone https://github.com/your-org/skillscan.git
cd skillscan

# 安装依赖
pip install -r requirements.txt

# 配置环境变量
cp .env.example .env
# 编辑 .env 文件配置 MongoDB 和 API 密钥
```

### Docker 部署

```bash
# 使用 Docker Compose 启动所有服务
docker-compose up -d

# 查看服务状态
docker-compose ps
```

## 使用方法

### CLI 命令

```bash
# 扫描本地目录
python -m src.main scan local --path /path/to/skills

# 扫描网络资源
python -m src.main scan network --url https://example.com/skills

# 使用LLM增强分析
python -m src.main scan local --path ./skills --use-llm

# 指定输出格式
python -m src.main scan local --path ./skills --output json --output-file results.json
```

### API 服务

```bash
# 启动API服务
python -m src.api.app

# 或使用uvicorn
uvicorn src.api.app:app --host 0.0.0.0 --port 8000
```

API端点：

| 方法 | 路径 | 描述 |
|------|------|------|
| GET | `/health` | 健康检查 |
| POST | `/api/v1/scan` | 提交扫描任务 |
| GET | `/api/v1/scan/{scan_id}` | 查询扫描状态 |
| GET | `/api/v1/skills` | 列出已扫描技能 |
| GET | `/api/v1/vulnerabilities` | 查询漏洞列表 |
| GET | `/api/v1/statistics` | 统计数据 |

## 项目结构

```
skillscan/
├── src/
│   ├── __init__.py
│   ├── main.py              # CLI入口
│   ├── config.py            # 配置管理
│   ├── api/                 # FastAPI REST接口
│   │   └── app.py
│   ├── collectors/          # 数据采集器
│   │   ├── local_collector.py
│   │   └── network_collector.py
│   ├── analyzers/           # 分析引擎
│   │   ├── static_analyzer.py
│   │   ├── llm_analyzer.py
│   │   └── hybrid_analyzer.py
│   ├── models/              # MongoDB数据模型
│   │   ├── skill.py
│   │   ├── vulnerability.py
│   │   └── database.py
│   ├── rules/               # 检测规则
│   │   └── detection_rules.py
│   ├── storage/             # 存储层
│   │   └── mongodb.py
│   └── preprocessors/       # 预处理
│       └── file_processor.py
├── tests/                   # 测试套件
│   ├── conftest.py
│   ├── test_detection_rules.py
│   ├── test_analyzers.py
│   ├── test_preprocessors.py
│   ├── test_models.py
│   └── test_integration.py
├── scripts/                 # 工具脚本
├── docs/                    # 文档
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── pyproject.toml
```

## 检测规则

检测规则位于 `src/rules/detection_rules.py`，包含60+条规则覆盖所有14种漏洞模式，支持中英文检测。

### 规则结构

```python
{
    "rule_id": "P1-001",
    "pattern": r"(?i)(ignore|disregard|override|bypass)\s+(previous|prior|all|system|safety)\s+(instructions?|prompts?|rules?|constraints?|checks?)",
    "category": "prompt_injection",
    "pattern_code": "P1",
    "severity": "high",
    "description_zh": "检测到指令覆盖模式",
    "description_en": "Detected instruction override pattern",
    "language": "en",
    "tags": ["instruction_override", "safety_bypass"],
    "confidence_boost": 1.2,
}
```

## 测试

```bash
# 运行所有测试
pytest tests/ -v

# 运行特定测试
pytest tests/test_detection_rules.py -v

# 运行带覆盖率报告
pytest tests/ --cov=src --cov-report=html
```

## 配置

### 环境变量

| 变量名 | 描述 | 默认值 |
|--------|------|--------|
| `MONGODB_URL` | MongoDB连接URL | `mongodb://localhost:27017` |
| `MONGODB_DB_NAME` | 数据库名 | `skillscan` |
| `REDIS_URL` | Redis连接URL | `redis://localhost:6379` |
| `LOG_LEVEL` | 日志级别 | `INFO` |
| `OPENAI_API_KEY` | OpenAI API密钥 (用于LLM分析) | - |
| `ANTHROPIC_API_KEY` | Anthropic API密钥 (用于LLM分析) | - |
| `MAX_FILE_SIZE` | 最大文件大小(字节) | `10485760` (10MB) |

## 架构设计

### 三阶段混合检测

```
┌─────────────────────────────────────────────────────────────────────┐
│                        SkillScan Architecture                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐   │
│  │   Collector   │───▶│ Preprocessor │───▶│   Analysis Engine    │   │
│  │ (Local/Net)   │    │ (File Parse) │    │ (Static → LLM → Hyb) │   │
│  └──────────────┘    └──────────────┘    └──────────────────────┘   │
│                                                     │                │
│                              ┌──────────────────────┼──────────┐    │
│                              │                      │          │    │
│                              ▼                      ▼          ▼    │
│                     ┌─────────────┐        ┌─────────────┐          │
│                     │   MongoDB   │◀───────│  Reporter   │          │
│                     │   Storage   │        │ (JSON/PDF)  │          │
│                     └─────────────┘        └─────────────┘          │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## 贡献

欢迎贡献！请查看 [CONTRIBUTING.md](CONTRIBUTING.md) 了解详情。

## 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件。

## 参考文献

- [Agent Skills in the Wild: An Empirical Study of Security Vulnerabilities at Scale](https://arxiv.org/html/2601.10338v1)
