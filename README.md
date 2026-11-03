# Trivy DB 查询服务

简体中文 | [English](README.en.md)

一个独立的 Trivy 漏洞数据库 HTTP 查询服务和数据库更新工具。它从 Trivy OCI 仓库下载数据库并在本地管理版本，无需安装 Trivy CLI。

### 功能

- 按漏洞 ID、软件包名称、版本或 Package URL（PURL）查询 Trivy DB。
- 支持单条查询和最多 100 条的批量查询。
- 从 Trivy OCI 镜像下载并校验数据库；确认新版本可用并完成切换后，删除旧版本，仅保留当前版本以节省磁盘空间。
- 支持定时更新、手动命令行更新，以及通过管理 API 立即更新。
- 支持 API Key、并发请求限制、优雅关闭和可配置日志。

### 环境要求

- Go 1.25.5 或更新版本。
- 首次启动或执行更新时，需要访问配置的 OCI 镜像仓库（默认 `ghcr.io/aquasecurity/trivy-db:2`）。

### 快速开始

先在 [`config.yaml`](config.yaml) 中将 `server.api_key` 改为自己的密钥。然后在项目根目录启动服务：

```sh
go run ./cmd/trivydb-api
```

服务默认监听 `http://localhost:8088`。首次启动会在本地数据库不可用时自动下载数据库，因此需要能够访问配置的 OCI 仓库。启动后可用以下命令查询漏洞：

```sh
curl "http://localhost:8088/api/v1/query?id=CVE-2025-1234" \
  -H "X-API-Key: your-api-key"
```

也可用 `Authorization: Bearer your-api-key` 传递密钥。若 `server.api_key` 留空，服务不会验证 API 请求。

### 构建与运行

在项目根目录执行：

```sh
go build -o trivydb-api ./cmd/trivydb-api
```

启动服务（默认读取当前目录下的 `config.yaml`）：

```sh
go run ./cmd/trivydb-api
```

也可以指定配置文件：

```sh
go run ./cmd/trivydb-api serve -c ./config.yaml
```

服务默认监听 `:8088`。启动时若本地还没有可用数据库，会先下载数据库再开始服务。收到 `Ctrl+C` 或终止信号后，服务会在配置的超时时间内优雅关闭。

### 一次性更新数据库

服务停止时，可执行一次下载、校验并激活数据库，然后退出：

```sh
go run ./cmd/trivydb-api update -c ./config.yaml
```

`update` 与服务内更新使用相同的暂存、校验和版本切换流程。新版本成功打开并激活后会清理旧版本；若更新失败，当前数据库仍会保留并恢复使用。命令行参数由 [Kong](https://github.com/alecthomas/kong) 解析。

### 配置

项目提供了 [`config.yaml`](config.yaml) 示例。请将其中的 `server.api_key` 设置为自己的密钥；留空会关闭 API 身份验证。配置文件中的相对数据库和日志路径以配置文件所在目录为基准解析。

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `server.addr` | `:8088` | HTTP 监听地址。 |
| `server.shutdown_timeout_seconds` | `10` | 优雅关闭超时时间（秒）。 |
| `server.max_concurrent_requests` | `100` | 最大并发请求数；设为 `0` 表示不限制，超过限制的请求返回 HTTP 503。 |
| `server.api_key` | 空 | API 密钥；留空时不启用身份验证。 |
| `database.dsn` | `./data/db.versions` | 数据库根目录；各数据库版本存放在其 `versions` 子目录中。 |
| `database.repository` | `ghcr.io/aquasecurity/trivy-db:2` | Trivy DB OCI 镜像引用。 |
| `database.update_interval` | `6h` | 定时更新间隔；设为 `0` 可关闭定时更新。 |
| `log.*` | 见配置文件 | 控制台和文件日志等级、格式、轮转与保留策略；`file_path: ""` 可关闭文件日志。 |

日志格式支持 `text`、`json`、`off`，也支持 `TLCM` 等 `slogs` 格式掩码。

### 查询 API

除公开的 `GET /healthz` 外，所有 API 路由都需要身份验证（若配置了 API Key）。可通过 `X-API-Key` 或 `Authorization: Bearer <密钥>` 传递密钥。成功和错误响应都使用 `{ "code", "msg", "data" }` JSON 信封。

#### 支持的查询参数

单条查询和批量查询中的每条查询都支持以下字段：

| 参数 | 说明 |
| --- | --- |
| `id` | 漏洞 ID，例如 `CVE-2025-1234`。可单独查询，也可与软件包条件组合筛选。 |
| `cve` | `id` 的别名。两者同时提供时，以 `id` 为准。 |
| `package` | 软件包名称。不限定生态系统时，会跨生态系统精确匹配名称。 |
| `version` | 软件包版本；必须与 `package` 或 `purl` 一起使用，只返回影响该版本的公告。 |
| `purl` | Package URL，用于指定软件包及其生态系统；PURL 中的版本可直接用于版本筛选。 |

查询至少需要 `id`、`cve`、`package`、`purl` 中的一个。`version` 不能单独使用。PURL 会限制生态系统；同时提供 `package` 或 `version` 时，值必须与 PURL 中的信息一致。

#### 单条查询

```sh
curl "http://localhost:8088/api/v1/query?id=CVE-2025-1234" \
  -H "X-API-Key: your-api-key"
```

支持的查询方式示例：

```http
GET /api/v1/query?id=CVE-2025-1234
GET /api/v1/query?cve=CVE-2025-1234
GET /api/v1/query?package=lodash
GET /api/v1/query?package=lodash&version=4.17.20
GET /api/v1/query?purl=pkg:npm/lodash@4.17.20
GET /api/v1/query?id=CVE-2025-1234&package=lodash&version=4.17.20
```
最后一个示例将漏洞 ID、软件包和版本组合使用，以筛选该软件包版本相关的匹配项。
也可以使用 `cve` 参数代替 `id`。查询至少需要漏洞 ID、软件包名称或 PURL 其中之一。PURL 会限定软件包生态系统；指定版本时，只返回影响该版本的公告。仅使用软件包名称时，会在各生态系统中进行精确名称匹配。

#### 批量查询

```sh
curl -X POST http://localhost:8088/api/v1/query \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: replace-with-your-api-key' \
  -d '{"queries":[{"id":"CVE-2025-1234"},{"purl":"pkg:npm/lodash@4.17.20"}]}'
```

批量请求需包含 1 至 100 条查询，且请求体不能超过 1 MiB。每条查询可使用上表中的字段及组合规则。

#### 响应格式

成功响应使用 `{ "code", "msg", "data" }` 信封。单条查询的 `data.results` 是结果数组；未找到匹配项时为空数组：

```json
{
  "code": "success",
  "msg": "ok",
  "data": {
    "results": [
      {
        "id": "CVE-2025-1234",
        "package_name": "lodash",
        "query_version": "4.17.20",
        "severity": "HIGH",
        "aliases": ["GHSA-example"]
      }
    ]
  }
}
```

结果对象始终包含 `id`。`package_name`、`query_version`、`aliases`、`title`、`description`、`severity`、`cvss`、`details` 和 `advisories` 等字段按数据库内容返回，空值字段可能省略。批量查询的 `data.results` 中，每项包含对应的 `query` 和该查询的 `results` 数组。错误响应的 `data` 为 `null`，例如：

```json
{
  "code": "invalid_query",
  "msg": "id, package, or purl is required",
  "data": null
}
```

#### 其他接口

| 方法与路径 | 说明 |
| --- | --- |
| `GET /healthz` | 健康检查，无需身份验证。 |
| `POST /api/v1/admin/update` | 立即下载并激活数据库；需要有效 API Key。 |

查询结果包含 Trivy DB 中可用的漏洞描述、严重级别、CVSS、别名、受影响版本、修复版本、公告和参考链接。服务使用 [`github.com/winezer0/slogs`](https://github.com/winezer0/slogs) 记录日志。
