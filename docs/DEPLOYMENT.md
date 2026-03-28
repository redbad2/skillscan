# SkillScan 部署指南

本文档详细介绍如何将 SkillScan 部署到全新环境中。

## 环境要求

| 组件 | 最低版本 | 推荐版本 | 说明 |
|------|----------|----------|------|
| Python | 3.10 | 3.11 | 运行时环境 |
| MongoDB | 6.0 | 7.0 | 数据持久化存储 |
| Redis | 7.0 | 7.2 | 缓存和任务队列 |
| Docker | 24.0 | 25.0 | 容器化部署（可选）|
| Docker Compose | 2.20 | 2.24 | 编排管理（可选）|

## 部署方式

### 方式一：Docker Compose 部署（推荐）

适用于生产环境和快速搭建开发环境。

```bash
# 1. 克隆仓库
git clone https://github.com/anomalyco/skillscan.git
cd skillscan

# 2. 配置环境变量
cp .env.example .env
# 编辑 .env 文件配置必要的密钥

# 3. 启动所有服务
docker-compose up -d

# 4. 查看服务状态
docker-compose ps

# 5. 查看日志
docker-compose logs -f skillscan
```

#### 启动的服务

| 服务 | 端口 | 说明 |
|------|------|------|
| skillscan | 8000 | API 服务 |
| mongodb | 27017 | 数据库 |
| redis | 6379 | 缓存/消息队列 |
| celery-worker | - | 异步任务处理（可选）|
| mongo-express | 8081 | MongoDB 管理界面（可选）|

#### 停止服务

```bash
docker-compose down

# 停止并删除数据卷
docker-compose down -v
```

### 方式二：手动部署

适用于开发调试或特殊定制场景。

#### 步骤 1：安装系统依赖

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    python3.11 python3.11-venv python3.11-dev \
    gcc g++ curl \
    git

# macOS
brew install python@3.11 git
```

#### 步骤 2：安装数据库

```bash
# Ubuntu/Debian - 安装 MongoDB
wget -qO - https://www.mongodb.org/static/pgp/server-7.0.asc | sudo apt-key add -
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list
sudo apt-get update
sudo apt-get install -y mongodb-org

# Ubuntu/Debian - 安装 Redis
sudo apt-get install -y redis-server

# macOS
brew install mongodb-community redis
```

#### 步骤 3：克隆并配置项目

```bash
# 克隆仓库
git clone https://github.com/anomalyco/skillscan.git
cd skillscan

# 创建虚拟环境
python3.11 -m venv venv
source venv/bin/activate

# 安装依赖
pip install -r requirements.txt

# 配置环境变量
cp .env.example .env
# 编辑 .env 文件配置必要的密钥
```

#### 步骤 4：配置环境变量

编辑 `.env` 文件，至少配置以下必需项：

```bash
# MongoDB 配置
MONGODB_URI=mongodb://localhost:27017
MONGODB_DATABASE=skillscan

# Redis 配置
REDIS_URL=redis://localhost:6379/0

# LLM 配置（用于增强分析）
OPENAI_API_KEY=your-openai-api-key
ANTHROPIC_API_KEY=your-anthropic-api-key

# API 配置
API_KEY=your-secure-api-key
```

#### 步骤 5：初始化数据库

```bash
# 启动 MongoDB
mkdir -p /data/db
mongod --dbpath /data/db --bind_ip 127.0.0.1 --fork --logpath /var/log/mongodb.log

# 启动 Redis
redis-server --daemonize yes
```

#### 步骤 6：验证安装

```bash
# 运行测试
pytest tests/ -v

# 预期输出：120 passed, 2 skipped
```

#### 步骤 7：启动服务

```bash
# 启动 API 服务
uvicorn src.api.app:app --host 0.0.0.0 --port 8000

# 或使用开发模式（热重载）
uvicorn src.api.app:app --reload --host 0.0.0.0 --port 8000
```

### 方式三：本地开发

最简部署方式，适用于快速测试。

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 配置环境变量
cp .env.example .env
# 编辑 .env 文件

# 3. 运行测试
pytest tests/ -v

# 4. CLI 扫描示例
python -m src.main scan local --path ./skills

# 5. 启动 API（可选）
python -m src.api.app
```

## 架构拓扑

```
┌─────────────────────────────────────────────────────────────┐
│                      SkillScan 部署架构                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   ┌─────────────┐     ┌────────────────────────────────┐  │
│   │   Client    │────▶│  API Server (:8000)             │  │
│   │  (浏览器/CLI) │     │  FastAPI + Uvicorn              │  │
│   └─────────────┘     └───────────────┬──────────────────┘  │
│                                       │                      │
│                    ┌──────────────────┼──────────────────┐   │
│                    ▼                  ▼                  ▼      │
│             ┌──────────┐       ┌──────────┐      ┌──────┐  │
│             │ MongoDB  │       │  Redis   │      │Celery│  │
│             │ (:27017) │       │ (:6379)  │      │Worker│  │
│             └──────────┘       └──────────┘      └──────┘  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## 配置参考

### 环境变量说明

| 变量名 | 必需 | 默认值 | 说明 |
|--------|------|--------|------|
| `MONGODB_URI` | 是 | `mongodb://localhost:27017` | MongoDB 连接地址 |
| `MONGODB_DATABASE` | 否 | `skillscan` | 数据库名称 |
| `REDIS_URL` | 是 | `redis://localhost:6379/0` | Redis 连接地址 |
| `OPENAI_API_KEY` | 可选 | - | OpenAI API 密钥（启用 LLM 分析）|
| `ANTHROPIC_API_KEY` | 可选 | - | Anthropic API 密钥 |
| `API_KEY` | 是 | - | API 认证密钥 |
| `LOG_LEVEL` | 否 | `INFO` | 日志级别 |

### 完整配置示例

```bash
# =============================================================================
# 应用配置
# =============================================================================
DEBUG=false
ENVIRONMENT=production
DATA_DIR=data
LOGS_DIR=logs

# =============================================================================
# MongoDB配置
# =============================================================================
MONGODB_URI=mongodb://localhost:27017
MONGODB_DATABASE=skillscan
MONGODB_MAX_POOL_SIZE=100

# =============================================================================
# Redis配置
# =============================================================================
REDIS_URL=redis://localhost:6379/0
REDIS_MAX_CONNECTIONS=50

# =============================================================================
# LLM配置
# =============================================================================
OPENAI_API_KEY=sk-xxxx
OPENAI_MODEL=gpt-4-turbo-preview
ANTHROPIC_API_KEY=sk-ant-xxxx
LLM_MAX_TOKENS=4000
LLM_TEMPERATURE=0.1

# =============================================================================
# 扫描配置
# =============================================================================
MAX_CONCURRENT_SCANS=100
RISK_THRESHOLD=0.5
CONFIDENCE_THRESHOLD=0.7

# =============================================================================
# API配置
# =============================================================================
API_HOST=0.0.0.0
API_PORT=8000
API_KEY=your-secure-random-key
API_RATE_LIMIT=100

# =============================================================================
# 日志配置
# =============================================================================
LOG_LEVEL=INFO
LOG_FILE=logs/skillscan.log
```

## 验证部署

### 健康检查

```bash
# 检查 API 服务
curl http://localhost:8000/api/v1/health

# 预期响应
# {"status": "healthy", "mongodb": "connected", "redis": "connected", "version": "1.0.0"}
```

### 功能测试

```bash
# 1. CLI 本地扫描
python -m src.main scan local --path ./tests/fixtures/skills

# 2. 使用 LLM 增强分析
python -m src.main scan local --path ./tests/fixtures/skills --use-llm

# 3. 指定输出格式
python -m src.main scan local --path ./tests/fixtures/skills --output json --output-file results.json

# 4. 查看统计
curl http://localhost:8000/api/v1/statistics
```

## 容器化说明

### Dockerfile

项目使用多阶段构建的 Dockerfile：

```dockerfile
FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y gcc g++ curl
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ ./src/
CMD ["uvicorn", "src.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Docker Compose 服务说明

| 服务 | 镜像 | 端口 | 数据卷 | 说明 |
|------|------|------|--------|------|
| skillscan | 本地构建 | 8000 | ./logs:/app/logs | API 服务 |
| mongodb | mongo:7.0 | 27017 | mongodb_data:/data/db | 数据库 |
| redis | redis:7-alpine | 6379 | redis_data:/data | 缓存 |
| celery-worker | 本地构建 | - | - | 异步任务（可选）|
| mongo-express | mongo-express:latest | 8081 | - | 管理界面（可选）|

### 常用 Docker 命令

```bash
# 构建镜像
docker-compose build

# 启动服务
docker-compose up -d

# 查看状态
docker-compose ps

# 查看日志
docker-compose logs -f skillscan

# 进入容器
docker exec -it skillscan-api /bin/bash

# 重启服务
docker-compose restart skillscan

# 停止服务
docker-compose down

# 完全清理（包括数据卷）
docker-compose down -v
```

## 故障排除

### MongoDB 连接失败

```bash
# 检查 MongoDB 状态
sudo systemctl status mongod

# 或手动启动
mongod --dbpath /data/db --bind_ip 127.0.0.1

# 检查端口占用
lsof -i :27017
```

### Redis 连接失败

```bash
# 检查 Redis 状态
sudo systemctl status redis-server

# 或手动启动
redis-server --daemonize yes

# 测试连接
redis-cli ping
# 预期响应：PONG
```

### 端口冲突

```bash
# 检查端口占用
lsof -i :8000

# 或使用不同端口启动
uvicorn src.api.app:app --port 8001
```

### 依赖安装失败

```bash
# 确保 pip 最新
pip install --upgrade pip

# 安装构建工具
pip install build

# 或使用国内镜像
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
```

## 生产环境建议

### 安全建议

1. **使用强 API 密钥**
   ```bash
   # 生成随机密钥
   openssl rand -hex 32
   ```

2. **配置 HTTPS**
   ```bash
   # 使用反向代理（如 Nginx）
   # 或直接在 Uvicorn 配置 TLS
   uvicorn src.api.app:app --ssl-certfile=cert.pem --ssl-keyfile=key.pem
   ```

3. **限制访问**
   ```bash
   # 配置防火墙
   ufw allow 8000/tcp
   ufw enable
   ```

### 性能优化

1. **增加 worker 数量**
   ```bash
   # 根据 CPU 核心数调整
   uvicorn src.api.app:app --workers 4
   ```

2. **配置连接池**
   ```bash
   MONGODB_MAX_POOL_SIZE=200
   REDIS_MAX_CONNECTIONS=100
   ```

3. **启用缓存**
   ```bash
   CACHE_TTL=3600
   ```

### 监控告警

建议配置：
- 日志收集（ELK/Graylog）
- 指标监控（Prometheus + Grafana）
- 告警通知（PagerDuty/Slack）

## 下一步

部署完成后，您可以：

- [使用 CLI 进行扫描](./usage.md)
- [集成 API 服务](./api.md)
- [配置检测规则](./rules.md)
