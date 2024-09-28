use std::env;

use axum::{extract::State, http::StatusCode, Router};
use sqlx::MySqlConnection;
use tracing::error;

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("SQLx error: {0}")]
    Sqlx(#[from] sqlx::Error),
}

impl axum::response::IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        let status = match self {
            Error::Sqlx(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        error!("{}", self);
        (status, format!("{}", self)).into_response()
    }
}

type Result<T, E = Error> = std::result::Result<T, E>;

async fn db_initialize(tx: &mut MySqlConnection) -> Result<()> {
    let sqls = [
        "DELETE FROM users WHERE id > 1000",
        "DELETE FROM posts WHERE id > 10000",
        "DELETE FROM comments WHERE id > 100000",
        "UPDATE users SET del_flg = 0",
        "UPDATE users SET del_flg = 1 WHERE id % 50 = 0",
    ];

    for sql in sqls.iter() {
        sqlx::query(sql).execute(&mut *tx).await?;
    }

    Ok(())
}

async fn get_initialize(State(AppState { pool, .. }): State<AppState>) -> Result<()> {
    let mut tx = pool.begin().await?;
    db_initialize(&mut tx).await?;

    Ok(())
}

fn build_mysql_options() -> sqlx::mysql::MySqlConnectOptions {
    let mut options = sqlx::mysql::MySqlConnectOptions::new()
        .host("localhost")
        .port(3306)
        .username("root")
        .password("")
        .database("isuconp");

    if let Ok(host) = env::var("ISUCONP_DB_HOST") {
        options = options.host(&host);
    }

    if let Ok(port) = env::var("ISUCONP_DB_PORT") {
        options =
            options.port(port.parse().expect(
                "Failed to read DB port number from an environment variable ISUCONP_DB_PORT.",
            ));
    }

    if let Ok(user) = env::var("ISUCONP_DB_USER") {
        options = options.username(&user);
    }
    if let Ok(password) = env::var("ISUCONP_DB_PASSWORD") {
        options = options.password(&password);
    }
    if let Ok(db_name) = env::var("ISUCONP_DB_NAME") {
        options = options.database(&db_name);
    }

    options
}

#[derive(Clone)]
struct AppState {
    pool: sqlx::mysql::MySqlPool,
}

#[tokio::main]
async fn main() {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "info,tower_http=debug,axum::rejection=trace");
    }
    tracing_subscriber::fmt::init();

    let pool = sqlx::mysql::MySqlPoolOptions::new()
        .connect_with(build_mysql_options())
        .await
        .expect("failed to connect db");

    let app = Router::new()
        .route("/initialize", axum::routing::get(get_initialize))
        .with_state(AppState { pool })
        .layer(tower_http::trace::TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
