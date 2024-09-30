use axum::{
    extract::State,
    http::{HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
    Form, Router,
};
use rand::prelude::*;
use serde::Serialize;
use shell_quote::Sh;
use sqlx::MySqlConnection;
use std::{collections::HashMap, env, process::Command};
use tower_http::services::ServeDir;
use tower_sessions::{MemoryStore, Session, SessionManagerLayer};
use tracing::error;

#[derive(thiserror::Error, Debug)]
enum CustomError {}
impl axum::response::IntoResponse for CustomError {
    fn into_response(self) -> Response {
        match self {}
    }
}

impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self.0.downcast::<CustomError>() {
            Ok(e) => e.into_response(),
            Err(e) => {
                error!("{} {}", e, e.backtrace());
                (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response()
            }
        }
    }
}

#[derive(Debug)]
struct AppError(anyhow::Error);

impl<E: Into<anyhow::Error>> From<E> for AppError {
    fn from(e: E) -> Self {
        Self(e.into())
    }
}

type Result<T, E = AppError> = std::result::Result<T, E>;

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

async fn try_login(
    account_name: &str,
    password: &str,
    tx: &mut MySqlConnection,
) -> Result<Option<User>> {
    let user = match sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE account_name = ? AND del_flg = 0",
    )
    .bind(account_name)
    .fetch_optional(&mut *tx)
    .await?
    {
        Some(user) => user,
        None => return Ok(None),
    };

    Ok(
        if calculate_passhash(&user.account_name, password) == user.passhash {
            Some(user)
        } else {
            None
        },
    )
}

fn secure_random_str(b: usize) -> String {
    let mut bytes = vec![0; b];
    thread_rng().fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

fn digest(src: &str) -> String {
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "echo -n {} | openssl dgst -sha512 | sed 's/^.*= //'",
            String::from_utf8(Sh::quote_vec(src)).unwrap()
        ))
        .output()
        .expect("Failed to execute openssl")
        .stdout;
    String::from_utf8(output).unwrap().trim_end().to_string()
}

fn calculate_salt(account_name: &str) -> String {
    digest(account_name)
}

fn calculate_passhash(account_name: &str, password: &str) -> String {
    digest(&(password.to_string() + ":" + &calculate_salt(account_name)))
}

async fn get_flash(session: &Session, key: &str) -> Result<String> {
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
        minijinja::context!(me, flash => get_flash(&session, "notice").await?),
    )?
    .into_response())
}

async fn post_login(
    session: Session,
    State(AppState { pool, .. }): State<AppState>,
    Form(form): Form<HashMap<String, String>>,
) -> Result<Response> {
    let mut conn = pool.acquire().await?;
    if is_login(&get_session_user(&session, &mut conn).await?) {
        return Ok(Redirect::new("/").into_response());
    }
    let user = try_login(
        form["account_name"].as_str(),
        form["password"].as_str(),
        &mut conn,
    )
    .await?;

    if let Some(user) = user {
        session.insert("user_id", user.id).await?;
        session.insert("csrf_token", secure_random_str(16)).await?;
        Ok(Redirect::new("/").into_response())
    } else {
        session
            .insert("notice", "アカウント名かパスワードが間違っています")
            .await?;
        Ok(Redirect::new("/login").into_response())
    }
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
    let session_layer = SessionManagerLayer::new(session_store).with_secure(false);

    let serve_dir = ServeDir::new("public");

    let app = Router::new()
        .route("/initialize", axum::routing::get(get_initialize))
        .route("/login", axum::routing::get(get_login))
        .route("/login", axum::routing::post(post_login))
        .with_state(AppState { pool })
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .layer(session_layer)
        .fallback_service(serve_dir);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
