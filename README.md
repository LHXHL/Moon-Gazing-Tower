# 望月塔 - Moon Gazing Tower

一个安全资产扫描与漏洞管理平台，基于 Go + React 构建。

## 作者信息

- **作者**: SantaVp3
- **团队**: NoSafe

## 功能模块

### 子域名扫描
- **主动枚举**: 使用 [ksubdomain](https://github.com/boy-hack/ksubdomain) 进行高速 DNS 爆破
- **被动收集**: 支持第三方 API 查询
  - FOFA
  - Hunter
  - Quake
  - Crt.sh
  - SecurityTrails
- **CDN 检测**: 识别目标是否使用 CDN
- **子域名接管检测**: 检测可能存在的子域名接管风险

### 端口扫描
- **扫描引擎**: 使用 [GoGo](https://github.com/chainreactors/gogo) 进行端口扫描
- **扫描模式**:
  - 快速扫描 (Top 100 端口)
  - Top 1000 端口扫描
  - 全端口扫描 (1-65535)
  - 自定义端口范围
- **服务识别**: GoGo 内置端口指纹识别

### Web 指纹识别
- 基于规则的 Web 指纹识别引擎
- 支持 HTTP 响应头、HTML 内容、Favicon Hash 等多种识别方式
- 识别 CMS、框架、中间件、编程语言等

### 敏感信息扫描
- 基于正则的敏感信息检测
- 支持检测:
  - API Key / Secret Key
  - 邮箱地址
  - 手机号码
  - 身份证号
  - 内网 IP
  - 数据库连接字符串等

### 漏洞扫描
- **扫描引擎**: 集成 [Nuclei](https://github.com/projectdiscovery/nuclei) 漏洞扫描器
- **弱口令检测**: 内置常见服务弱口令检测
- **POC 管理**: 支持自定义 POC 模板

### 爬虫模块
- **爬虫引擎**: 集成 [Katana](https://github.com/projectdiscovery/katana) 网页爬虫
- 自动发现 URL、API 接口、表单等

### 任务管理
- 支持扫描任务的创建、暂停、恢复、取消
- 扫描结果实时展示
- 任务进度追踪

### 资产管理
- 支持 IP、域名、URL 等多种资产类型
- 资产标签和分组
- 扫描结果与资产关联

### 漏洞管理
- 漏洞状态流转 (待确认 → 已确认 → 已修复 → 已忽略)
- 漏洞严重程度分级 (严重/高危/中危/低危/信息)
- CVE/CNVD 关联

## 技术栈

### 后端
- **Go 1.21+**
- **Gin** - Web 框架
- **MongoDB** - 数据存储
- **Redis** - 缓存

### 前端
- **React 18** + **TypeScript**
- **Vite** - 构建工具
- **Shadcn/UI** + **TailwindCSS** - UI 组件
- **React Query** - 数据请求
- **Recharts** - 图表

### 依赖工具
| 工具 | 用途 |
|------|------|
| [ksubdomain](https://github.com/boy-hack/ksubdomain) | 子域名爆破 |
| [GoGo](https://github.com/chainreactors/gogo) | 端口扫描 |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | 漏洞扫描 |
| [Katana](https://github.com/projectdiscovery/katana) | 网页爬虫 |
| [httpx](https://github.com/projectdiscovery/httpx) | HTTP 探测 |

## 快速开始

### 使用 Docker Compose

```bash
# 克隆项目
git clone https://github.com/SantaVp3/Moon-Gazing-Tower.git
cd Moon-Gazing-Tower

# 启动服务
docker-compose up -d

# 查看日志
docker-compose logs -f
```

启动后访问:
- **前端**: http://localhost
- **后端 API**: http://localhost:8080
- **默认账号**: admin / admin123

### 本地开发

#### 后端

```bash
cd backend

# 安装依赖
go mod download

# 启动 MongoDB 和 Redis
docker run -d --name mongodb -p 27017:27017 mongo:6.0
docker run -d --name redis -p 6379:6379 redis:7-alpine

# 运行
go run main.go
```

#### 前端

```bash
cd frontend

# 安装依赖
npm install

# 开发模式
npm run dev

# 构建
npm run build
```

## 项目结构

```
Moon-Gazing-Tower/
├── backend/
│   ├── api/              # HTTP 处理器
│   ├── config/           # 配置文件
│   │   └── dicts/        # 字典文件
│   ├── database/         # 数据库连接
│   ├── middleware/       # 中间件
│   ├── models/           # 数据模型
│   ├── router/           # 路由定义
│   ├── scanner/          # 扫描模块
│   │   ├── portscan/     # 端口扫描 (GoGo)
│   │   ├── subdomain/    # 子域名扫描 (ksubdomain)
│   │   ├── fingerprint/  # Web 指纹识别
│   │   ├── webscan/      # Web 扫描 (Katana, 敏感信息)
│   │   └── vulnscan/     # 漏洞扫描 (Nuclei)
│   ├── service/          # 业务逻辑
│   │   └── pipeline/     # 扫描流水线
│   ├── tools/            # 外部工具二进制
│   │   ├── darwin/       # macOS
│   │   └── linux/        # Linux
│   └── utils/            # 工具函数
├── frontend/
│   └── src/
│       ├── api/          # API 封装
│       ├── components/   # 组件
│       ├── pages/        # 页面
│       └── store/        # 状态管理
└── docker-compose.yml
```

## 配置说明

### 后端配置 (config/config.yaml)

```yaml
server:
  port: 8080
  mode: debug

mongodb:
  uri: mongodb://localhost:27017
  database: moongazing

redis:
  addr: localhost:6379
  password: ""
  db: 0

jwt:
  secret: your-jwt-secret
  expire: 24h
```

### 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| SERVER_PORT | 8080 | 服务端口 |
| MONGODB_URI | mongodb://localhost:27017 | MongoDB 连接 |
| REDIS_ADDR | localhost:6379 | Redis 地址 |
| JWT_SECRET | - | JWT 密钥 |

## 注意事项

- 本工具仅供授权的安全测试使用
- 请勿用于未授权的渗透测试
- 使用者需自行承担相关法律责任

## License

MIT License
