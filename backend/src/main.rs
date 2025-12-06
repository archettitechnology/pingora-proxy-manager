mod acme;
mod api;
mod auth;
mod db;
mod proxy;
mod state;
mod stream_manager; // Added

use crate::proxy::DynamicProxy;
use crate::state::{AppState, ProxyConfig, HostConfig, LocationConfig};
use crate::stream_manager::StreamManager; // Added
use pingora::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};
use metrics_exporter_prometheus::PrometheusBuilder;

fn main() {
    // 0. .env 파일 로드 (가장 먼저 실행)
    dotenvy::dotenv().ok();

    // 1. 로깅 초기화 (File + Stdout)
    let file_appender = tracing_appender::rolling::daily("logs", "access.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stdout)
                .with_filter(tracing_subscriber::filter::LevelFilter::INFO)
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(non_blocking)
                .json() // 파일에는 JSON으로 저장 (구조화된 로그)
                .with_filter(tracing_subscriber::filter::LevelFilter::INFO)
        )
        .init();

    tracing::info!("Starting Pingora Proxy Manager...");

    // 메트릭 레코더 초기화
    let recorder_handle = PrometheusBuilder::new()
        .install_recorder()
        .expect("failed to install Prometheus recorder");

    // Tokio 런타임 시작
    let rt = tokio::runtime::Runtime::new().unwrap();
    
    // 상태 공유 객체
    let state = Arc::new(AppState::new());
    
    // 초기화용 state 복제 (메인 state는 아래 Pingora Proxy에서 사용)
    let state_for_init = state.clone();

    rt.block_on(async move {
        // 2. DB 초기化
        let db_config = db::DatabaseConfig::from_env().expect("Failed to parse database configuration");
        tracing::info!("🗄️ Database type: {:?}", db_config.db_type);
        tracing::info!("🗄️ Database URL: {}", db_config.url.split('@').last().unwrap_or("***"));
        
        let pool = db::init_db(&db_config).await.expect("Failed to init DB");
        
        // 초기 관리자 계정 생성 (없으면)
        let admin_exists = db::get_user(&pool, "admin").await.unwrap().is_some();
        if !admin_exists {
            let hash = auth::hash_password("changeme").unwrap();
            db::create_user(&pool, "admin", &hash).await.unwrap();
            tracing::info!("👤 Created default admin user: admin / changeme");
        }

        // 3. 초기 상태 로드
        let hosts_result = db::get_all_hosts(&pool).await;
        let locations_result = db::get_all_locations(&pool).await;
        let access_lists_result = db::get_all_access_lists(&pool).await;
        let clients_result = db::get_access_list_clients(&pool).await;
        let ips_result = db::get_access_list_ips(&pool).await;
        let headers_result = db::get_all_headers(&pool).await;

        if let (Ok(rows), Ok(loc_rows), Ok(al_rows), Ok(client_rows), Ok(ip_rows), Ok(header_rows)) = (
            hosts_result, 
            locations_result, 
            access_lists_result, 
            clients_result, 
            ips_result, 
            headers_result
        ) {
            // 1. Locations
            let mut locations_map: HashMap<i64, Vec<LocationConfig>> = HashMap::new();
            for loc in loc_rows {
                locations_map.entry(loc.host_id).or_default().push(LocationConfig {
                    path: loc.path,
                    target: loc.target,
                    scheme: loc.scheme,
                    rewrite: loc.rewrite,
                });
            }

            // 2. Access Lists
            let mut access_lists = HashMap::new();
            
            // Group Clients and IPs by list_id
            let mut clients_map: HashMap<i64, Vec<crate::state::AccessListClientConfig>> = HashMap::new();
            for c in client_rows {
                clients_map.entry(c.list_id).or_default().push(crate::state::AccessListClientConfig {
                    username: c.username,
                    password_hash: c.password_hash,
                });
            }

            let mut ips_map: HashMap<i64, Vec<crate::state::AccessListIpConfig>> = HashMap::new();
            for ip in ip_rows {
                ips_map.entry(ip.list_id).or_default().push(crate::state::AccessListIpConfig {
                    ip: ip.ip_address,
                    action: ip.action,
                });
            }

            for al in al_rows {
                access_lists.insert(al.id, crate::state::AccessListConfig {
                    id: al.id,
                    name: al.name,
                    clients: clients_map.remove(&al.id).unwrap_or_default(),
                    ips: ips_map.remove(&al.id).unwrap_or_default(),
                });
            }

            // 3. Headers (grouped by host_id for ProxyConfig)
            let mut headers_map: HashMap<i64, Vec<crate::state::HeaderConfig>> = HashMap::new();
            for h in header_rows {
                headers_map.entry(h.host_id).or_default().push(crate::state::HeaderConfig {
                    id: h.id,
                    name: h.name,
                    value: h.value,
                    target: h.target,
                });
            }

            let mut hosts = HashMap::new();
            for row in rows {
                let locs = locations_map.remove(&row.id).unwrap_or_default();
                let host_headers = headers_map.get(&row.id).cloned().unwrap_or_default();
                hosts.insert(row.domain, HostConfig {
                    id: row.id,
                    target: row.target,
                    scheme: row.scheme,
                    locations: locs,
                    ssl_forced: row.ssl_forced,
                    redirect_to: row.redirect_to,
                    redirect_status: row.redirect_status as u16,
                    access_list_id: row.access_list_id,
                    headers: host_headers,
                });
            }
            state_for_init.update_config(ProxyConfig { hosts, access_lists, headers: headers_map });
            tracing::info!("✅ Initial configuration loaded from DB");
        } else {
            tracing::warn!("⚠️ Failed to load initial configuration from DB");
        }

        // Stream Manager 초기화
        let stream_manager = Arc::new(StreamManager::new(pool.clone()));
        stream_manager.reload_streams().await; // 초기 로드

        // 4. API 서버 실행 (81번 포트)
        let pool_for_api = pool.clone();
        let state_for_api = state_for_init.clone();
        let recorder_handle_for_api = recorder_handle.clone();
        let stream_manager_for_api = stream_manager.clone(); // API용 복제

        tokio::spawn(async move {
            let app = api::router(state_for_api, pool_for_api, recorder_handle_for_api, stream_manager_for_api);
            let listener = tokio::net::TcpListener::bind("0.0.0.0:81").await.unwrap();
            tracing::info!("🎮 Control Plane (API) running on port 81");
            axum::serve(listener, app).await.unwrap();
        });

        // 5. 자동 갱신 스케줄러 (매 1시간마다 체크)
        let pool_for_acme = pool.clone();
        let state_for_acme = state_for_init.clone();
        tokio::spawn(async move {
            let acme_manager = acme::AcmeManager::new(
                state_for_acme, 
                pool_for_acme.clone(), 
                "admin@example.com".to_string() 
            );
            
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
                
                tracing::info!("⏰ Checking for expiring certificates...");
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
                let renewal_threshold = now + 30 * 24 * 60 * 60; 

                match db::get_expiring_certs(&pool_for_acme, renewal_threshold).await {
                    Ok(certs) => {
                        for (domain, provider_id) in certs {
                            tracing::info!("♻️ Renewing certificate for {} (Provider: {:?})", domain, provider_id);
                            if let Err(e) = acme_manager.request_certificate(&domain, provider_id).await {
                                tracing::error!("❌ Failed to renew certificate for {}: {}", domain, e);
                            }
                        }
                    },
                    Err(e) => tracing::error!("❌ Failed to check expiring certificates: {}", e),
                }
            }
        });

        // 6. 메트릭 수집 스케줄러 (매 1분마다 DB 저장)
        let pool_for_stats = pool.clone();
        let state_for_stats = state_for_init.clone();
        tokio::spawn(async move {
            loop {
                // 1분 대기 (정각에 맞추는 로직은 아님)
                tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
                
                let (reqs, bytes, s2xx, s4xx, s5xx) = state_for_stats.metrics.reset();
                
                // 데이터가 있을 때만 저장 (옵션)
                if reqs > 0 {
                     let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
                     if let Err(e) = db::insert_traffic_stat(&pool_for_stats, now, reqs, bytes, s2xx, s4xx, s5xx).await {
                         tracing::error!("❌ Failed to save traffic stats: {}", e);
                     } else {
                         tracing::debug!("📊 Traffic stats saved: {} reqs", reqs);
                     }
                }
            }
        });
    });

    // 7. Pingora 서버 실행 (메인 스레드 점유)
    let mut my_server = Server::new(None).unwrap();
    my_server.bootstrap();

    let mut my_proxy = http_proxy_service(
        &my_server.configuration,
        DynamicProxy {
            state: state.clone(), // API가 업데이트하는 그 state를 공유
        },
    );

    my_proxy.add_tcp("0.0.0.0:8080");
    my_proxy.add_tls("0.0.0.0:443", "data/certs/default.crt", "data/certs/default.key").unwrap();

    my_server.add_service(my_proxy);
    tracing::info!("🚀 Data Plane (Proxy) running on port 8080 (HTTP) and 443 (HTTPS)");
    my_server.run_forever();
}
