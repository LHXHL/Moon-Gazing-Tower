# 望月楼 - Moon Gazing Tower

一个现代化的安全扫描平台，基于五层架构设计，支持分布式扫描任务调度和漏洞管理。

## 作者信息

- **作者**: SantaVp3
- **团队**: NoSafe

## 系统架构

```
┌─────────────────────────────────────────────────────────────────┐
│                        望月楼 - 安全扫描平台                       │
├─────────────────────────────────────────────────────────────────┤
│  第五层 - 展示层                                                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │ Dashboard │ │ 资产管理  │ │ 漏洞管理  │ │ 任务管理  │           │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘           │
├─────────────────────────────────────────────────────────────────┤
│  第四层 - 服务层                                                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │ 用户服务  │ │ 资产服务  │ │ 任务服务  │ │ 漏洞服务  │           │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘           │
├─────────────────────────────────────────────────────────────────┤
│  第三层 - 调度层                                                  │
│  ┌──────────────────────────────────────────────────┐           │
│  │              任务调度引擎 (Task Scheduler)         │           │
│  │   ┌─────────┐  ┌─────────┐  ┌─────────┐          │           │
│  │   │ 节点管理 │  │ 负载均衡 │  │ 任务分发 │          │           │
│  │   └─────────┘  └─────────┘  └─────────┘          │           │
│  └──────────────────────────────────────────────────┘           │
├─────────────────────────────────────────────────────────────────┤
│  第二层 - 扫描层                                                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │ 端口扫描  │ │ Web扫描   │ │ POC验证   │ │ 指纹识别  │           │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘           │
├─────────────────────────────────────────────────────────────────┤
│  第一层 - 数据层                                                  │
│  ┌──────────────────┐  ┌──────────────────┐                     │
│  │    MongoDB       │  │      Redis       │                     │
│  │   (主数据存储)    │  │   (缓存/会话)    │                     │
│  └──────────────────┘  └──────────────────┘                     │
└─────────────────────────────────────────────────────────────────┘
```

## 技术栈

### 后端
- **Go 1.21** - 主要编程语言
- **Gin** - Web 框架
- **MongoDB** - 数据持久化
- **Redis** - 缓存和会话管理
- **JWT** - 身份认证

### 前端
- **React 18** - UI 框架
- **TypeScript** - 类型安全
- **Vite** - 构建工具
- **Shadcn/UI** - 组件库
- **TailwindCSS** - 样式框架
- **React Query** - 服务端状态管理
- **Zustand** - 客户端状态管理
- **Recharts** - 数据可视化

## 快速开始

### 使用 Docker Compose (推荐)

```bash
# 克隆项目
git clone https://github.com/your-repo/moon-gazing-tower.git
cd moon-gazing-tower

# 启动所有服务
docker-compose up -d

# 查看日志
docker-compose logs -f

# 停止服务
docker-compose down
```

启动后访问:
- **前端**: http://localhost
- **后端API**: http://localhost:8080
- **默认管理员**: admin / admin123

### 本地开发

#### 后端

```bash
cd backend

# 安装依赖
go mod download

# 启动 MongoDB 和 Redis (使用 Docker)
docker run -d --name mongodb -p 27017:27017 mongo:6.0
docker run -d --name redis -p 6379:6379 redis:7-alpine

# 运行后端
go run cmd/main.go
```

#### 前端

```bash
cd frontend

# 安装依赖
npm install

# 启动开发服务器
npm run dev
```

## 项目结构

```
moon-gazing-tower/
├── backend/                 # Go 后端
│   ├── cmd/                 # 入口文件
│   ├── config/              # 配置
│   ├── internal/
│   │   ├── api/             # API 处理器
│   │   ├── middleware/      # 中间件
│   │   ├── models/          # 数据模型
│   │   ├── router/          # 路由
│   │   ├── services/        # 业务逻辑
│   │   └── utils/           # 工具函数
│   └── pkg/
│       └── database/        # 数据库连接
├── frontend/                # React 前端
│   ├── src/
│   │   ├── api/             # API 服务
│   │   ├── components/      # 组件
│   │   ├── layouts/         # 布局
│   │   ├── lib/             # 工具库
│   │   ├── pages/           # 页面
│   │   └── store/           # 状态管理
│   └── public/              # 静态资源
├── scripts/                 # 脚本
└── docker-compose.yml       # Docker 编排
```

## API 文档

### 认证

| 方法 | 路径 | 描述 |
|------|------|------|
| POST | /api/auth/login | 用户登录 |
| GET | /api/auth/me | 获取当前用户信息 |
| POST | /api/auth/logout | 退出登录 |

### 资产管理

| 方法 | 路径 | 描述 |
|------|------|------|
| GET | /api/assets | 获取资产列表 |
| POST | /api/assets | 创建资产 |
| GET | /api/assets/:id | 获取资产详情 |
| PUT | /api/assets/:id | 更新资产 |
| DELETE | /api/assets/:id | 删除资产 |

### 任务管理

| 方法 | 路径 | 描述 |
|------|------|------|
| GET | /api/tasks | 获取任务列表 |
| POST | /api/tasks | 创建任务 |
| GET | /api/tasks/:id | 获取任务详情 |
| PUT | /api/tasks/:id | 更新任务 |
| DELETE | /api/tasks/:id | 删除任务 |
| POST | /api/tasks/:id/start | 启动任务 |
| POST | /api/tasks/:id/stop | 停止任务 |

### 漏洞管理

| 方法 | 路径 | 描述 |
|------|------|------|
| GET | /api/vulnerabilities | 获取漏洞列表 |
| GET | /api/vulnerabilities/:id | 获取漏洞详情 |
| PUT | /api/vulnerabilities/:id | 更新漏洞状态 |
| DELETE | /api/vulnerabilities/:id | 删除漏洞 |

### POC 管理

| 方法 | 路径 | 描述 |
|------|------|------|
| GET | /api/pocs | 获取 POC 列表 |
| POST | /api/pocs | 创建 POC |
| GET | /api/pocs/:id | 获取 POC 详情 |
| PUT | /api/pocs/:id | 更新 POC |
| DELETE | /api/pocs/:id | 删除 POC |

### 节点管理

| 方法 | 路径 | 描述 |
|------|------|------|
| GET | /api/nodes | 获取节点列表 |
| POST | /api/nodes | 注册节点 |
| GET | /api/nodes/:id | 获取节点详情 |
| PUT | /api/nodes/:id | 更新节点 |
| DELETE | /api/nodes/:id | 删除节点 |
| POST | /api/nodes/:id/heartbeat | 节点心跳 |

## 功能特性

### 资产管理
- ✅ 支持 IP、域名、URL、网段等多种资产类型
- ✅ 资产标签和分组管理
- ✅ 资产导入导出
- ✅ 资产状态追踪

### 任务调度
- ✅ 多种扫描类型支持 (端口扫描、Web扫描、POC验证等)
- ✅ 定时任务调度
- ✅ 任务优先级管理
- ✅ 分布式任务分发

### 漏洞管理
- ✅ 漏洞状态流转 (待确认→已确认→已修复)
- ✅ 漏洞严重程度分级
- ✅ CVE/CNVD 关联
- ✅ 漏洞报告导出

### 节点管理
- ✅ 扫描节点注册和心跳
- ✅ 节点状态监控
- ✅ 负载均衡

### 用户管理
- ✅ 基于角色的访问控制 (RBAC)
- ✅ 用户权限管理
- ✅ 操作日志审计

## 环境变量

### 后端

| 变量 | 默认值 | 描述 |
|------|--------|------|
| SERVER_PORT | 8080 | 服务端口 |
| GIN_MODE | debug | 运行模式 |
| MONGODB_URI | mongodb://localhost:27017 | MongoDB 连接地址 |
| REDIS_ADDR | localhost:6379 | Redis 地址 |
| REDIS_PASSWORD | | Redis 密码 |
| JWT_SECRET | | JWT 密钥 |

### 前端

| 变量 | 默认值 | 描述 |
|------|--------|------|
| VITE_API_BASE_URL | /api | API 基础路径 |

## License

MIT License
