use axum::{
    extract::State,
    http::{HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
    Router,
};
use serde::Serialize;
use sqlx::MySqlConnection;
use std::env;
use tower_http::services::ServeDir;
use tower_sessions::{MemoryStore, Session, SessionManagerLayer};
use tracing::error;

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("SQLx error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("Session error: {0}")]
    Session(#[from] tower_sessions::session::Error),
    #[error("Template error: {0}")]
    Template(#[from] minijinja::Error),
}

impl axum::response::IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        let status = match self {
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };

        error!("{}", self);
        (status, format!("{}", self)).into_response()
    }
}

type Result<T, E = Error> = std::result::Result<T, E>;

// axum::response::Redirect doesn't support 302 status code.
struct Redirect(HeaderValue);
impl Redirect {
    fn new(uri: &str) -> Self {
        Self(HeaderValue::from_str(uri).expect("Failed to create a HeaderValue from a string."))
    }
}
impl IntoResponse for Redirect {
    fn into_response(self) -> Response {
        (StatusCode::FOUND, [("location", self.0)]).into_response()
    }
}

fn render_template<S: Serialize>(tmpl_name: &str, context: S) -> Result<Html<String>> {
    let mut env = minijinja::Environment::new();
    env.set_loader(minijinja::path_loader("templates"));
    let tmpl = env.get_template(tmpl_name)?;
    Ok(Html(tmpl.render(context)?))
}

#[derive(sqlx::FromRow, Serialize)]
struct User {
    id: i64,
    account_name: String,
    passhash: String,
    authority: i64,
    del_flg: i64,
    created_at: chrono::DateTime<chrono::Utc>,
}

fn is_login(user: &Option<User>) -> bool {
    user.is_some()
}

async fn get_session_user(session: &Session, tx: &mut MySqlConnection) -> Result<Option<User>> {
    let uid = session.get::<i64>("user_id").await?;

    if let Some(uid) = uid {
        let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
            .bind(uid)
            .fetch_one(&mut *tx)
            .await?;

        Ok(Some(user))
    } else {
        Ok(None)
    }
}

async fn get_flush(session: &Session, key: &str) -> Result<String> {
    Ok(match session.get(key).await? {
        Some(value) => {
            session.remove::<String>(key).await?;
            value
        }
        None => "".to_string(),
    })
}

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
    let mut conn = pool.acquire().await?;
    db_initialize(&mut conn).await?;

    Ok(())
}

async fn get_login(
    session: Session,
    State(AppState { pool, .. }): State<AppState>,
) -> Result<Response> {
    let mut conn = pool.acquire().await?;
    let me = get_session_user(&session, &mut conn).await?;
    if is_login(&me) {
        return Ok(Redirect::new("/").into_response());
    }

    Ok(render_template(
        "login.html",
        minijinja::context!(me, flush => get_flush(&session, "notice").await?),
    )?
    .into_response())
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

    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store);

    let serve_dir = ServeDir::new("public");

    let app = Router::new()
        .route("/initialize", axum::routing::get(get_initialize))
        .route("/login", axum::routing::get(get_login))
        .with_state(AppState { pool })
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .layer(session_layer)
        .fallback_service(serve_dir);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
