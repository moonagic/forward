# Go 端口转发器

一个动态的、API 驱动的端口转发器，带有 Web UI，使用 Go 编写。

此工具允许您基于 YAML 配置文件转发网络端口（TCP/UDP）。它提供了一个现代化的 Web 界面来实时管理配置，无需重启服务。

## 特性

- **动态配置**：通过简单的 `config.yml` 文件管理转发规则。
- **TCP & UDP 支持**：转发 TCP 和 UDP 流量，每个规则都可配置。
- **现代化 Web 界面**：带有玻璃态设计的清洁、响应式 Web UI，用于查看、添加、编辑和删除转发规则。
- **热重载**：配置可以从 Web UI 即时更改和应用，无需任何服务中断。
- **IP 白名单**：通过为每个规则指定允许的源 IP 范围（CIDR 记号）来限制对转发端口的访问。
- **临时 IP 池**：带有持久化存储的动态 IP 管理 - 临时允许的 IP 在服务重启后依然保留。
- **基于会话的身份验证**：具有安全会话管理和双重身份验证支持（会话 + 基础认证）的现代登录系统。
- **可配置池大小**：通过配置文件自定义临时 IP 池大小。
- **深色/浅色模式**：Web UI 包含主题切换器，支持桌面和移动设备的完全响应式设计。
- **单一二进制部署**：Web 界面嵌入到 Go 二进制文件中，使部署就像复制单个文件一样简单。
- **Systemd 服务**：提供了 `forwarder.service` 文件，便于在 Linux 上作为后台服务部署。

## 开始使用

### 先决条件

- Go 1.16 或更高版本（由于使用了 `embed` 包）。

### 配置

应用程序使用同一目录中的 `config.yml` 文件进行配置。

```yaml
# 管理 Web UI 的服务地址。
admin_addr: "127.0.0.1:9090"

# Web 界面和 API 的身份验证凭据。
basic_auth:
  username: "admin"
  password: "password"

# 临时 IP 池的大小（如果未指定，默认为 10）。
temp_ip_pool_size: 10

# 转发规则列表。
forwards:
  # 此规则为 DNS 转发 TCP 和 UDP 流量。
  - protocols: ["tcp", "udp"]
    from: "0.0.0.0:5353"
    to: "8.8.8.8:53"
    allowed_ips:
      - "127.0.0.1/32"
      - "192.168.1.0/24"

  # 此规则仅为 Web 服务器转发 TCP 流量。
  - protocols: ["tcp"]
    from: "0.0.0.0:8080"
    to: "127.0.0.1:80"
    # 如果 allowed_ips 为空或省略，则允许所有源 IP。
    allowed_ips: []
```

### 构建和运行

提供了 `Makefile` 来简化常见任务。

**构建二进制文件：**

这将把应用程序编译成一个名为 `forwarder` 的可执行文件。

```bash
make build
```

**运行应用程序进行开发：**

此命令将直接编译和运行应用程序。

```bash
make run
```

运行后，转发服务将处于活动状态，Web UI 将在配置中 `admin_addr` 指定的地址上可用。系统将提示您使用配置的 `basic_auth` 部分中指定的凭据登录。

### 主要功能使用

**临时 IP 池**：Web 界面包含一个临时 IP 管理部分，您可以：
- 添加需要临时访问转发端口的 IP 地址
- 查看当前允许的临时 IP，带有视觉优先级指示器
- 在不再需要访问时删除 IP
- 添加到临时池的 IP 会自动保存到 `ip_pool.json` 并在服务重启后保持

**身份验证**：应用程序支持双重身份验证：
- **Web 界面**：具有安全 cookie 管理的现代基于会话的登录
- **API 访问**：用于程序化访问和自动化脚本的 HTTP 基础认证

**响应式设计**：Web 界面采用现代玻璃态设计，在桌面和移动设备上无缝工作，支持主题切换。

## 作为 Systemd 服务部署

包含了一个 `forwarder.service` 文件，用于在现代 Linux 系统上作为托管服务运行应用程序。

1. 将编译的 `forwarder` 二进制文件和您的 `config.yml` 文件放入类似 `/opt/forwarder` 的目录中。
2. 将 `forwarder.service` 文件复制到 `/etc/systemd/system/`。
3. 按照 `.service` 文件注释中的说明创建专用用户并设置权限。
4. 启用并启动服务：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now forwarder.service
```

## Makefile 命令

- `make build`    - 为生产构建应用程序。
- `make run`      - 运行应用程序进行开发。
- `make clean`    - 清理构建产物。
- `make tidy`     - 整理 Go 模块依赖项。
- `make help`     - 显示此帮助消息。