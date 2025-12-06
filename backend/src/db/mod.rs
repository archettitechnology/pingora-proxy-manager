use sqlx::AnyPool;
use std::error::Error;

pub mod config;
pub mod hosts;
pub mod access_lists;
pub mod users;
pub mod certs;
pub mod streams;
pub mod stats;

pub use config::{DatabaseConfig, DatabaseType};

pub type DbPool = AnyPool;

pub use hosts::*;
pub use access_lists::*;
pub use users::*;
pub use certs::*;
pub use streams::*;
pub use stats::*;

/// DB 초기화 및 스키마 생성
pub async fn init_db(config: &DatabaseConfig) -> Result<DbPool, Box<dyn Error>> {
    // DB 커넥션 풀 생성 (database-agnostic using AnyPool)
    let pool = AnyPool::connect(&config.url).await?;

    let is_mysql = matches!(config.db_type, DatabaseType::Mysql);
    
    // AUTO_INCREMENT syntax differs between SQLite and MySQL
    let auto_increment = if is_mysql { "AUTO_INCREMENT" } else { "AUTOINCREMENT" };
    let default_timestamp = if is_mysql { "CURRENT_TIMESTAMP" } else { "(strftime('%s', 'now'))" };
    let integer_type = if is_mysql { "BIGINT" } else { "INTEGER" };
    let text_type = if is_mysql { "VARCHAR(255)" } else { "TEXT" };
    let long_text_type = if is_mysql { "TEXT" } else { "TEXT" };
    let boolean_type = if is_mysql { "BOOLEAN" } else { "BOOLEAN" };

    // 호스트 테이블 생성
    let create_hosts = format!(
        r#"
        CREATE TABLE IF NOT EXISTS hosts (
            id {} PRIMARY KEY {},
            domain {} NOT NULL UNIQUE,
            target {} NOT NULL,
            scheme {} NOT NULL DEFAULT 'http',
            ssl_forced {} NOT NULL DEFAULT 0,
            redirect_to {},
            redirect_status {} NOT NULL DEFAULT 301,
            access_list_id {},
            FOREIGN KEY(access_list_id) REFERENCES access_lists(id)
        )
        "#,
        integer_type, auto_increment, text_type, text_type, text_type,
        boolean_type, text_type, integer_type, integer_type
    );
    sqlx::query(&create_hosts).execute(&pool).await?;

    // 마이그레이션: access_list_id 컬럼이 없으면 추가 (기존 DB 호환성)
    if !is_mysql {
        // SQLite에서만 실행 (MySQL은 초기 CREATE에 포함됨)
        let _ = sqlx::query("ALTER TABLE hosts ADD COLUMN access_list_id INTEGER").execute(&pool).await;
    }

    // Locations (경로별 라우팅) 테이블 생성
    let create_locations = format!(
        r#"
        CREATE TABLE IF NOT EXISTS locations (
            id {} PRIMARY KEY {},
            host_id {} NOT NULL,
            path {} NOT NULL,
            target {} NOT NULL,
            scheme {} NOT NULL DEFAULT 'http',
            rewrite {} NOT NULL DEFAULT 0,
            FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
        )
        "#,
        integer_type, auto_increment, integer_type, text_type, text_type, text_type, boolean_type
    );
    sqlx::query(&create_locations).execute(&pool).await?;

    // Stream (TCP/UDP) 테이블 생성
    let create_streams = format!(
        r#"
        CREATE TABLE IF NOT EXISTS streams (
            id {} PRIMARY KEY {},
            listen_port {} NOT NULL UNIQUE,
            forward_host {} NOT NULL,
            forward_port {} NOT NULL,
            protocol {} NOT NULL DEFAULT 'tcp'
        )
        "#,
        integer_type, auto_increment, integer_type, text_type, integer_type, text_type
    );
    sqlx::query(&create_streams).execute(&pool).await?;

    // Access Lists 테이블
    let create_access_lists = format!(
        r#"
        CREATE TABLE IF NOT EXISTS access_lists (
            id {} PRIMARY KEY {},
            name {} NOT NULL UNIQUE
        )
        "#,
        integer_type, auto_increment, text_type
    );
    sqlx::query(&create_access_lists).execute(&pool).await?;

    // Access List Clients (Basic Auth)
    let create_access_list_clients = format!(
        r#"
        CREATE TABLE IF NOT EXISTS access_list_clients (
            id {} PRIMARY KEY {},
            list_id {} NOT NULL,
            username {} NOT NULL,
            password_hash {} NOT NULL,
            FOREIGN KEY(list_id) REFERENCES access_lists(id) ON DELETE CASCADE
        )
        "#,
        integer_type, auto_increment, integer_type, text_type, long_text_type
    );
    sqlx::query(&create_access_list_clients).execute(&pool).await?;

    // Access List IPs (Allow/Deny)
    let create_access_list_ips = format!(
        r#"
        CREATE TABLE IF NOT EXISTS access_list_ips (
            id {} PRIMARY KEY {},
            list_id {} NOT NULL,
            ip_address {} NOT NULL,
            action {} NOT NULL CHECK(action IN ('allow', 'deny')),
            FOREIGN KEY(list_id) REFERENCES access_lists(id) ON DELETE CASCADE
        )
        "#,
        integer_type, auto_increment, integer_type, text_type, text_type
    );
    sqlx::query(&create_access_list_ips).execute(&pool).await?;

    // Headers (Custom Headers)
    let create_headers = format!(
        r#"
        CREATE TABLE IF NOT EXISTS headers (
            id {} PRIMARY KEY {},
            host_id {} NOT NULL,
            name {} NOT NULL,
            value {} NOT NULL,
            target {} NOT NULL CHECK(target IN ('request', 'response')),
            FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
        )
        "#,
        integer_type, auto_increment, integer_type, text_type, long_text_type, text_type
    );
    sqlx::query(&create_headers).execute(&pool).await?;

    // DNS Providers (Certbot DNS Plugins)
    let create_dns_providers = format!(
        r#"
        CREATE TABLE IF NOT EXISTS dns_providers (
            id {} PRIMARY KEY {},
            name {} NOT NULL,
            provider_type {} NOT NULL,
            credentials {} NOT NULL,
            created_at {} NOT NULL DEFAULT {}
        )
        "#,
        integer_type, auto_increment, text_type, text_type, long_text_type,
        integer_type, default_timestamp
    );
    sqlx::query(&create_dns_providers).execute(&pool).await?;

    // Custom Certs
    let create_custom_certs = format!(
        r#"
        CREATE TABLE IF NOT EXISTS custom_certs (
            id {} PRIMARY KEY {},
            domain {} NOT NULL UNIQUE,
            cert_path {} NOT NULL,
            key_path {} NOT NULL,
            created_at {} NOT NULL
        )
        "#,
        integer_type, auto_increment, text_type, text_type, text_type, integer_type
    );
    sqlx::query(&create_custom_certs).execute(&pool).await?;

    // 기존 인증서 테이블 (Let's Encrypt 용)
    let create_certs = format!(
        r#"
        CREATE TABLE IF NOT EXISTS certs (
            id {} PRIMARY KEY {},
            domain {} NOT NULL UNIQUE,
            expires_at {} NOT NULL,
            provider_id {}
        )
        "#,
        integer_type, auto_increment, text_type, integer_type, integer_type
    );
    sqlx::query(&create_certs).execute(&pool).await?;

    // 마이그레이션: provider_id 컬럼 추가
    if !is_mysql {
        let _ = sqlx::query("ALTER TABLE certs ADD COLUMN provider_id INTEGER").execute(&pool).await;
    }

    // 사용자 테이블 생성 (로그인용) - role 추가
    let create_users = format!(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id {} PRIMARY KEY {},
            username {} NOT NULL UNIQUE,
            password_hash {} NOT NULL,
            role {} NOT NULL DEFAULT 'viewer',
            created_at {} NOT NULL DEFAULT {},
            last_login {}
        )
        "#,
        integer_type, auto_increment, text_type, long_text_type, text_type,
        integer_type, default_timestamp, integer_type
    );
    sqlx::query(&create_users).execute(&pool).await?;

    // 마이그레이션: role, created_at, last_login 컬럼 추가 (기존 DB 호환성)
    if !is_mysql {
        let _ = sqlx::query("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin'").execute(&pool).await;
        let _ = sqlx::query("ALTER TABLE users ADD COLUMN created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))").execute(&pool).await;
        let _ = sqlx::query("ALTER TABLE users ADD COLUMN last_login INTEGER").execute(&pool).await;
    }

    // 감사 로그(Audit Log) 테이블 생성
    let create_audit_logs = format!(
        r#"
        CREATE TABLE IF NOT EXISTS audit_logs (
            id {} PRIMARY KEY {},
            timestamp {} NOT NULL DEFAULT {},
            user_id {},
            username {} NOT NULL,
            action {} NOT NULL,
            resource_type {} NOT NULL,
            resource_id {},
            details {},
            ip_address {}
        )
        "#,
        integer_type, auto_increment, integer_type, default_timestamp,
        integer_type, text_type, text_type, text_type, text_type, long_text_type, text_type
    );
    sqlx::query(&create_audit_logs).execute(&pool).await?;

    // 인덱스 추가 (조회 속도 향상)
    let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs (timestamp)")
        .execute(&pool)
        .await;
    let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_logs_username ON audit_logs (username)")
        .execute(&pool)
        .await;

    // 트래픽 통계 테이블 생성 (시계열)
    let create_traffic_stats = format!(
        r#"
        CREATE TABLE IF NOT EXISTS traffic_stats (
            id {} PRIMARY KEY {},
            timestamp {} NOT NULL,
            total_requests {} NOT NULL,
            total_bytes {} NOT NULL,
            status_2xx {} NOT NULL,
            status_4xx {} NOT NULL,
            status_5xx {} NOT NULL
        )
        "#,
        integer_type, auto_increment, integer_type, integer_type, integer_type,
        integer_type, integer_type, integer_type
    );
    sqlx::query(&create_traffic_stats).execute(&pool).await?;

    // 인덱스 추가 (조회 속도 향상)
    let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_traffic_stats_timestamp ON traffic_stats (timestamp)")
        .execute(&pool)
        .await;

    Ok(pool)
}
