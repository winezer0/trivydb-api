# Trivy DB Query Service

[简体中文](README.md) | English

An independent HTTP query service and updater for the Trivy vulnerability database. It downloads and manages database versions from the Trivy OCI repository locally; the Trivy CLI is not required.

### Features

- Query the Trivy DB by vulnerability ID, package name, version, or Package URL (PURL).
- Support single and batch queries, with up to 100 queries per batch.
- Download and validate the database from a Trivy OCI image. After the new version is confirmed usable and activated, remove old versions and keep only the current one to reduce disk usage.
- Support scheduled updates, one-shot command-line updates, and immediate updates through an admin API.
- Provide API key authentication, request concurrency limits, graceful shutdown, and configurable logging.

### Requirements

- Go 1.25.5 or newer.
- Access to the configured OCI image repository for the initial database download and updates. The default is `ghcr.io/aquasecurity/trivy-db:2`.

### Quick start

Set `server.api_key` in [`config.yaml`](config.yaml) to your own secret, then start the service from the project root:

```sh
go run ./cmd/trivydb-api serve
```

The service listens on `http://localhost:8088` by default. If no usable local database is available, it downloads one on startup, so the configured OCI repository must be reachable. Query a vulnerability with:

```sh
curl "http://localhost:8088/api/v1/query?id=CVE-2025-1234" \
  -H "X-API-Key: your-api-key"
```

You can also send the key as `Authorization: Bearer your-api-key`. If `server.api_key` is empty, API requests are not authenticated.

### Build and run

Run from the project root:

```sh
go build -o trivydb-api ./cmd/trivydb-api
```

Start the service (it reads `config.yaml` from the current directory by default):

```sh
go run ./cmd/trivydb-api serve
```

To specify a configuration file:

```sh
go run ./cmd/trivydb-api serve -c ./config.yaml
```

The service listens on `:8088` by default. If no usable local database is available, it downloads one before serving requests. On `Ctrl+C` or a termination signal, the service shuts down gracefully within the configured timeout.

### One-shot database update

When the service is stopped, download, validate, and activate the database once, then exit:

```sh
go run ./cmd/trivydb-api update-db -c ./config.yaml
```

The `update-db` command uses the same staging, validation, and version switching flow as service updates. After the new version opens and is activated, old versions are removed; if an update fails, the existing database remains available. Specify either `serve` or `update-db` explicitly. Command-line parsing uses [Kong](https://github.com/alecthomas/kong).

### Configuration

The repository includes a [`config.yaml`](config.yaml) example. Set `server.api_key` to your own secret; leaving it empty disables API authentication. Relative database and log paths are resolved from the configuration file's directory.

| Setting | Default | Description |
| --- | --- | --- |
| `server.addr` | `:8088` | HTTP listen address. |
| `server.shutdown_timeout_seconds` | `10` | Graceful shutdown timeout in seconds. |
| `server.max_concurrent_requests` | `100` | Maximum concurrent requests; `0` disables the limit. Excess requests receive HTTP 503. |
| `server.api_key` | empty | API key; an empty value disables authentication. |
| `database.dsn` | `./data/db.versions` | Database root directory; versions are stored in its `versions` subdirectory. |
| `database.repository` | `ghcr.io/aquasecurity/trivy-db:2` | Trivy DB OCI image reference. |
| `database.update_interval` | `6h` | Scheduled update interval; `0` disables scheduled updates. |
| `database.update_proxy` | empty | Optional proxy used only for Trivy DB downloads. Supports `http://`, `https://`, `socks5://`, and `socks5h://` URLs. When empty, Go's standard proxy environment variables are used. |
| `log.*` | See config file | Console and file log levels, formats, rotation, and retention; set `file_path: ""` to disable file logging. |

For example, set `database.update_proxy` to `http://127.0.0.1:7890` or `socks5h://127.0.0.1:1080`. Proxy credentials can be included in the URL, such as `http://user:password@proxy.example:8080`. The proxy affects database downloads only; query API traffic is unchanged.

Log formats include `text`, `json`, `off`, and `slogs` masks such as `TLCM`.

### Query API

All routes except the public `GET /healthz` require authentication when an API key is configured. Send the key in `X-API-Key` or `Authorization: Bearer <key>`. Successful and error responses use the JSON envelope `{ "code", "msg", "data" }`.

#### Supported query parameters

Single queries and each query in a batch support these fields:

| Parameter | Description |
| --- | --- |
| `id` | Vulnerability ID, such as `CVE-2025-1234`. Can be queried by itself or combined with package filters. |
| `cve` | Alias for `id`. If both are provided, `id` takes precedence. |
| `package` | Package name. Without an ecosystem restriction, the name is matched exactly across ecosystems. |
| `version` | Package version; must be used with `package` or `purl`. Only advisories affecting that version are returned. |
| `purl` | Package URL that identifies a package and its ecosystem. A version in the PURL can be used for version filtering. |

Each query must include at least one of `id`, `cve`, `package`, or `purl`. `version` cannot be used by itself. A PURL restricts the ecosystem; any supplied `package` or `version` must match the information in the PURL.

#### Single query

```sh
curl "http://localhost:8088/api/v1/query?id=CVE-2025-1234" \
  -H "X-API-Key: your-api-key"
```

Supported query examples:

```http
GET /api/v1/query?id=CVE-2025-1234
GET /api/v1/query?cve=CVE-2025-1234
GET /api/v1/query?package=lodash
GET /api/v1/query?package=lodash&version=4.17.20
GET /api/v1/query?purl=pkg:npm/lodash@4.17.20
GET /api/v1/query?id=CVE-2025-1234&package=lodash&version=4.17.20
```
The last example combines a vulnerability ID, package, and version to filter matching advisories for that package version.

#### Query latency on the current database

These are single-request measurements against the current Trivy DB from the local Windows service (database version `20261103T093641.961787100`, `trivy.db` about 2 GiB). Requests were sent over loopback without an API key:

| Query type | Test parameters | Response time |
| --- | --- | ---: |
| `id` only | `id=CVE-2021-23337` | 10.89 s |
| `cve` only | `cve=CVE-2021-23337` | 15.66 s |
| `package` only | `package=lodash` | 4.78 ms |
| Package + version | `package=lodash&version=4.17.20` | 3.07 ms |
| PURL | `purl=pkg:npm/lodash@4.17.20` | 2.38 ms |
| ID + package + version | `id=CVE-2021-23337&package=lodash&version=4.17.20` | 2.69 ms |
| `version` only | `version=4.17.20` | Unsupported; returns HTTP 400 |

Each value is a single observation; the operating system file cache was not cleared. Since requests were tested in table order, the preceding full ID scan may have warmed the cache for later package/PURL queries. Those timings are warm-cache references, not cold-cache measurements, and vary with storage, cache state, and system load. A bare `id`/`cve` query scans advisories to match aliases, which is substantially slower on a large database. Add `package` (and preferably `version`) to an ID query, or use a PURL, to take the package-index path.

#### Batch query

```sh
curl -X POST http://localhost:8088/api/v1/query \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: replace-with-your-api-key' \
  -d '{"queries":[{"id":"CVE-2025-1234"},{"purl":"pkg:npm/lodash@4.17.20"}]}'
```

A batch must contain 1 to 100 queries and the request body must not exceed 1 MiB. Each query uses the fields and combination rules listed above.

#### Response format

Successful responses use the `{ "code", "msg", "data" }` envelope. For a single query, `data.results` is an array; it is empty when there are no matches:

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

Each result always contains `id`. Fields such as `package_name`, `query_version`, `aliases`, `title`, `description`, `severity`, `cvss`, `details`, and `advisories` depend on the database contents; empty fields may be omitted. In a batch response, each item in `data.results` contains the corresponding `query` and its `results` array. Error responses have `data: null`, for example:

```json
{
  "code": "invalid_query",
  "msg": "id, package, or purl is required",
  "data": null
}
```

#### Other endpoints

| Method and path | Description |
| --- | --- |
| `GET /healthz` | Public health check. |
| `POST /api/v1/admin/update` | Download and activate the database immediately; requires a valid API key. |

Results include the descriptions, severity, CVSS, aliases, affected and fixed version data, advisories, and references available in the Trivy DB. Logging uses [`github.com/winezer0/slogs`](https://github.com/winezer0/slogs).
