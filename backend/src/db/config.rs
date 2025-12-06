use std::error::Error;

#[derive(Debug, Clone)]
pub enum DatabaseType {
    Sqlite,
    Mysql,
}

#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub db_type: DatabaseType,
    pub url: String,
}

impl DatabaseConfig {
    /// Parse database configuration from environment variables
    pub fn from_env() -> Result<Self, Box<dyn Error>> {
        let db_type_str = std::env::var("DATABASE_TYPE").unwrap_or_else(|_| "sqlite".to_string());
        
        let db_type = match db_type_str.to_lowercase().as_str() {
            "mysql" | "mariadb" => DatabaseType::Mysql,
            "sqlite" => DatabaseType::Sqlite,
            _ => return Err(format!("Unsupported DATABASE_TYPE: {}", db_type_str).into()),
        };

        let url = match db_type {
            DatabaseType::Sqlite => {
                std::env::var("DATABASE_URL")
                    .unwrap_or_else(|_| "sqlite:data/data.db?mode=rwc".to_string())
            }
            DatabaseType::Mysql => {
                // Build MySQL URL from individual components or use full URL
                if let Ok(url) = std::env::var("DATABASE_URL") {
                    url
                } else {
                    let host = std::env::var("MYSQL_HOST").unwrap_or_else(|_| "localhost".to_string());
                    let port = std::env::var("MYSQL_PORT").unwrap_or_else(|_| "3306".to_string());
                    let user = std::env::var("MYSQL_USER").unwrap_or_else(|_| "pingora".to_string());
                    let password = std::env::var("MYSQL_PASSWORD").unwrap_or_else(|_| "".to_string());
                    let database = std::env::var("MYSQL_DATABASE").unwrap_or_else(|_| "pingora_proxy".to_string());
                    
                    if password.is_empty() {
                        format!("mysql://{}@{}:{}/{}", user, host, port, database)
                    } else {
                        format!("mysql://{}:{}@{}:{}/{}", user, password, host, port, database)
                    }
                }
            }
        };

        Ok(DatabaseConfig { db_type, url })
    }
}
