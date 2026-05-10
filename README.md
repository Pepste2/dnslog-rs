# DNSLog Dashboard

> 基于 [adysec/dnslog-rs](https://github.com/adysec/dnslog-rs) 的二开版本，感谢原作者 [adysec](https://github.com/adysec) 的贡献。

## 项目简介

DNSLog Dashboard 是一个基于 Rust 的 DNS 日志记录平台，集成了 DNS 服务和 Web 仪表盘，主要用于捕获和记录 DNS 查询日志。该项目支持自动注册用户、生成唯一子域名以及实时展示 DNS 日志，适用于安全测试、信息外传及漏洞验证等场景。

## 二开更新内容

### v2.3.0 - DNS 回复 & Bug 修复

- **可配置 DNS 回复地址**：新增 `dns_response` 配置项，匹配的子域名返回自定义 A 记录（如 C2 地址），而非默认的 NXDOMAIN
- **修复 DNS 响应 message_id 不匹配**：使用 `Header::response_from_request()` 替代 `Header::new()`，确保响应 ID 与请求一致，客户端可正常接收回复
- **修复记录暴增问题**：仅记录 A/ANY 类型查询，过滤 AAAA/CNAME 等解析器噪声；对非 A 查询返回 NOERROR 空应答，避免解析器重试导致的记录洪水

### v2.2.0 - 配置化 & 子域名管理

- **配置文件支持**：新增 `config.toml`，支持域名、端口、DNS 回复地址等配置
- **命令行参数**：使用 clap 解析启动参数，优先级高于配置文件
- **子域名删除**：支持在 Web 面板中删除已有子域名及其关联日志
- **刷新保持子域名**：页面刷新后子域名和历史记录保持不变

### v2.1.0 - IP 地理定位 & 体验优化

- **IP 地理位置解析**：异步调用 ip-api.com 解析来源 IP 的地理位置，结果缓存并写入数据库
- **UTC+8 时间戳**：所有日志时间改为上海时区显示
- **修复复制按钮**：使用事件委托替代内联 onclick，解决动态内容复制失效问题
- **跨平台编译修复**：reqwest 切换为 rustls-tls，避免 Linux 下 OpenSSL 依赖问题

### v2.0.0 - UI 重构

- **全新深色主题**：GitHub 风格深色配色，毛玻璃效果卡片
- **中文界面**：全站中文化
- **可配置域名**：支持自定义域名后缀，不再硬编码
- **自动注册**：首次访问自动注册并跳转携带 token
- **实时刷新**：DNS 请求到达后自动更新日志展示
- **点击复制**：子域名、Token、回调地址一键复制
- **回调接口**：`/api/callback/<subdomain>` 返回最近日志 JSON，用于 OOB 验证

### 移除功能

- **TLS 支持**：已移除内置 TLS，建议通过 Caddy/Nginx 反向代理实现 HTTPS

## DNS 配置方法

1. **配置 A 记录允许通过域名访问 web 页面：**

通过添加如下 A 记录，将子域名（如 dnslog.xxx.com）指向平台 Web 服务的服务器 IP，实现页面访问。

```bash
# 名称    类型    内容
dnslog    A      xxx.xxx.xxx.xxx
```

2. **配置 NS 服务器：**

通过如下记录，将指定域（如 dns.xxx.com）的权威 DNS 服务器指向自建的 DNS 服务器，从而接收并记录所有针对该域及其子域的 DNS 查询请求。

```bash
# 名称    类型    内容
ns1       A      xxx.xxx.xxx.xxx
ns2       A      xxx.xxx.xxx.xxx
dns       NS     ns1.xxx.com
dns       NS     ns2.xxx.com
```
<img width="1263" height="366" alt="image" src="https://github.com/user-attachments/assets/42db69d8-bc3a-4ff1-9d52-525af0ad3840" />

3. **查看接收到的 DNS 请求结果：**

当目标系统在探测过程中触发对 `*.dns.xxx.com` 的解析请求时，请求将被路由至自建的 DNS 服务器，平台即可记录并显示这些请求日志。

> 注：如对方使用的 DNS 服务器存在负载均衡的情况，可能造成大量 dnslog 请求记录，并非存在多个触发点。

## 配置说明

### 配置文件 `config.toml`

```toml
# 域名后缀（生成的子域名格式：随机字符.{domain}）
domain = "example.com"

# DNS 服务端口（环境变量: DNS_PORT）
dns_port = 53

# Web 端口（环境变量: WEB_PORT）
web_port = 8888

# DNS 查询回复地址（匹配的子域名返回此 IP，环境变量: DNS_RESPONSE）
dns_response = "127.0.0.1"
```

### 命令行参数

```bash
dnslog-rs --domain example.com --dns-port 53 --web-port 8888 --dns-response 127.0.0.1
```

优先级：命令行参数 > 配置文件 > 环境变量

## 安装与构建

### 编译环境依赖

- **Rust 环境：** 推荐使用最新稳定版 Rust 和 Cargo。
- **SQLite 数据库：** 程序会在运行目录下自动生成 `dnslog.db` 数据库文件。

### 构建 & 运行

```bash
git clone https://github.com/Pepste2/dnslog-rs.git
cd dnslog-rs
cargo build --release
./target/release/dnslog-rs
```

### 使用 Caddy 反向代理（HTTPS）

```Caddyfile
dnslog.example.com {
    reverse_proxy localhost:8888
}
```

## 致谢

- 原项目：[adysec/dnslog-rs](https://github.com/adysec/dnslog-rs)
- 原作者：[adysec](https://github.com/adysec)
