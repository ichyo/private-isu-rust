use axum::{
    extract::{Path, Query, State},
    http::{HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
    Form, Router,
};
use minijinja::value::ViaDeserialize;
use rand::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use shell_quote::Sh;
use sqlx::MySqlConnection;
use std::{collections::HashMap, env, process::Command};
use tower_http::services::ServeDir;
use tower_sessions::{cookie::time::Duration, Expiry, MemoryStore, Session, SessionManagerLayer};
use tracing::error;

#[derive(thiserror::Error, Debug)]
enum AppError {}
impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {}
    }
}

impl axum::response::IntoResponse for Error {
    fn into_response(self) -> Response {
        match self.0.downcast::<AppError>() {
            Ok(e) => e.into_response(),
            Err(e) => {
                error!("Error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response()
            }
        }
    }
}

#[derive(Debug)]
struct Error(anyhow::Error);

impl<E: Into<anyhow::Error>> From<E> for Error {
    fn from(e: E) -> Self {
        Self(e.into())
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

const POSTS_PER_PAGE: usize = 20;

#[derive(sqlx::FromRow, Serialize, Deserialize, Debug, Clone, Default)]
struct User {
    id: i64,
    account_name: String,
    passhash: String,
    authority: i64,
    del_flg: i64,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(sqlx::FromRow, Serialize, Deserialize, Debug, Clone, Default)]
struct Post {
    id: i64,
    user_id: i64,
    #[sqlx(default)]
    imgdata: Vec<u8>,
    body: String,
    mime: String,
    created_at: chrono::DateTime<chrono::Utc>,
    #[sqlx(skip)]
    comment_count: i64,
    #[sqlx(skip)]
    comments: Vec<Comment>,
    #[sqlx(skip)]
    user: User,
    #[sqlx(skip)]
    csrf_token: String,
}

#[derive(sqlx::FromRow, Serialize, Deserialize, Debug, Clone, Default)]
struct Comment {
    id: i64,
    post_id: i64,
    user_id: i64,
    comment: String,
    created_at: chrono::DateTime<chrono::Utc>,
    #[sqlx(skip)]
    user: User,
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

fn validate_user(account_name: &str, password: &str) -> bool {
    Regex::new(r"\A[0-9a-zA-Z_]{3,}\z")
        .unwrap()
        .is_match(account_name)
        && Regex::new(r"\A[0-9a-zA-Z_]{6,}\z")
            .unwrap()
            .is_match(password)
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

async fn get_flash(session: &Session, key: &str) -> Result<String> {
    Ok(match session.get(key).await? {
        Some(value) => {
            session.remove::<String>(key).await?;
            value
        }
        None => "".to_string(),
    })
}

async fn make_posts(
    tx: &mut MySqlConnection,
    results: &[Post],
    csrf_token: String,
    all_comments: bool,
) -> Result<Vec<Post>> {
    let mut posts = vec![];
    for p in results {
        let mut p = p.clone();
        p.comment_count =
            sqlx::query_scalar("SELECT COUNT(*) AS `count` FROM `comments` WHERE `post_id` = ?")
                .bind(p.id)
                .fetch_one(&mut *tx)
                .await?;

        let mut query =
            "SELECT * FROM `comments` WHERE `post_id` = ? ORDER BY `created_at` DESC".to_string();
        if !all_comments {
            query += " LIMIT 3";
        }
        let mut comments = sqlx::query_as::<_, Comment>(&query)
            .bind(p.id)
            .fetch_all(&mut *tx)
            .await?;

        for c in comments.iter_mut() {
            c.user = sqlx::query_as::<_, User>("SELECT * FROM `users` WHERE `id` = ?")
                .bind(c.user_id)
                .fetch_one(&mut *tx)
                .await?;
        }

        comments.reverse();

        p.comments = comments;

        p.user = sqlx::query_as::<_, User>("SELECT * FROM `users` WHERE `id` = ?")
            .bind(p.user_id)
            .fetch_one(&mut *tx)
            .await?;

        p.csrf_token = csrf_token.clone();

        if p.user.del_flg == 0 {
            posts.push(p);
        }
        if posts.len() >= POSTS_PER_PAGE {
            break;
        }
    }
    Ok(posts)
}

fn image_url(p: ViaDeserialize<Post>) -> String {
    let ext = match p.mime.as_str() {
        "image/jpeg" => ".jpg",
        "image/png" => ".png",
        "image/gif" => ".gif",
        _ => "",
    };
    format!("/image/{}{}", p.id, ext)
}

fn is_login(user: &Option<User>) -> bool {
    user.is_some()
}

async fn get_csrf_token(session: &Session) -> String {
    match session.get::<String>("csrf_token").await {
        Ok(Some(token)) => token,
        _ => "".to_string(),
    }
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

fn render_template<S: Serialize>(tmpl_name: &str, context: S) -> Result<Html<String>> {
    let mut env = minijinja::Environment::new();
    env.set_loader(minijinja::path_loader("templates"));
    env.add_function("image_url", image_url);
    let tmpl = env.get_template(tmpl_name)?;
    Ok(Html(tmpl.render(context)?))
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

async fn get_register(
    session: Session,
    State(AppState { pool, .. }): State<AppState>,
) -> Result<Response> {
    let mut conn = pool.acquire().await?;
    if is_login(&get_session_user(&session, &mut conn).await?) {
        return Ok(Redirect::new("/").into_response());
    }

    Ok(render_template(
        "register.html",
        minijinja::context!(flash => get_flash(&session, "notice").await?),
    )?
    .into_response())
}

async fn post_register(
    session: Session,
    State(AppState { pool, .. }): State<AppState>,
    Form(form): Form<HashMap<String, String>>,
) -> Result<Response> {
    let mut conn = pool.acquire().await?;
    if is_login(&get_session_user(&session, &mut conn).await?) {
        return Ok(Redirect::new("/").into_response());
    }

    let account_name = form["account_name"].as_str();
    let password = form["password"].as_str();

    let validated = validate_user(account_name, password);
    if !validated {
        session
            .insert(
                "notice",
                "アカウント名は3文字以上、パスワードは6文字以上である必要があります",
            )
            .await?;
        return Ok(Redirect::new("/register").into_response());
    }

    let exists: Option<u8> = sqlx::query_scalar("SELECT 1 FROM users WHERE `account_name` = ?")
        .bind(account_name)
        .fetch_optional(&mut *conn)
        .await?;

    if let Some(_) = exists {
        session
            .insert("notice", "アカウント名がすでに使われています")
            .await?;
        return Ok(Redirect::new("/register").into_response());
    }

    let query = "INSERT INTO `users` (`account_name`, `passhash`) VALUES (?,?)";
    let result = sqlx::query(query)
        .bind(account_name)
        .bind(calculate_passhash(account_name, password))
        .execute(&mut *conn)
        .await?;

    let uid = result.last_insert_id();
    session.insert("user_id", uid).await?;
    session.insert("csrf_token", secure_random_str(16)).await?;

    Ok(Redirect::new("/").into_response())
}

async fn get_logout(session: Session) -> Result<Response> {
    session.delete().await?;
    session.set_expiry(Some(Expiry::OnInactivity(Duration::seconds(-1))));
    Ok(Redirect::new("/").into_response())
}

async fn get_index(
    session: Session,
    State(AppState { pool, .. }): State<AppState>,
) -> Result<Response> {
    let mut conn = pool.acquire().await?;
    let me = get_session_user(&session, &mut conn).await?;

    let results = sqlx::query_as::<_, Post>(
        "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM posts ORDER BY `created_at` DESC"
    ).fetch_all(&mut *conn).await?;

    let posts = make_posts(&mut conn, &results, get_csrf_token(&session).await, false).await?;

    Ok(render_template(
        "index.html",
        minijinja::context!(me, posts, csrf_token => get_csrf_token(&session).await, flash => get_flash(&session, "notice").await?),
    )?
    .into_response())
}

async fn get_account_name(
    session: Session,
    Path(account_name): Path<String>,
    State(AppState { pool, .. }): State<AppState>,
) -> Result<Response> {
    if !account_name.starts_with("@") {
        return Ok(StatusCode::NOT_FOUND.into_response());
    }
    let account_name = &account_name[1..];

    let mut conn = pool.acquire().await?;
    let user =
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE account_name = ? AND `del_flg` = 0")
            .bind(account_name)
            .fetch_optional(&mut *conn)
            .await?;

    let user = match user {
        Some(user) => user,
        None => return Ok(StatusCode::NOT_FOUND.into_response()),
    };

    let results = sqlx::query_as::<_, Post>(
        "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM posts WHERE `user_id` = ? ORDER BY `created_at` DESC"
    ).bind(user.id).fetch_all(&mut *conn).await?;

    let posts = make_posts(&mut conn, &results, get_csrf_token(&session).await, true).await?;

    let comment_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) AS `count` FROM `comments` WHERE `user_id` = ?")
            .bind(user.id)
            .fetch_one(&mut *conn)
            .await?;

    let post_ids: Vec<i64> = sqlx::query_scalar("SELECT `id` FROM `posts` WHERE `user_id` = ?")
        .bind(user.id)
        .fetch_all(&mut *conn)
        .await?;
    let post_count = post_ids.len();

    let mut commented_count = 0;
    if post_count > 0 {
        let placeholder = (0..post_count).map(|_| "?").collect::<Vec<_>>().join(", ");

        let query = format!(
            "SELECT COUNT(*) AS `count` FROM `comments` WHERE `post_id` IN ({})",
            placeholder
        );

        let mut query = sqlx::query_scalar(&query);

        for id in post_ids.iter() {
            query = query.bind(id);
        }

        commented_count = query.fetch_one(&mut *conn).await?;
    }

    let me = get_session_user(&session, &mut conn).await?;

    Ok(render_template(
        "user.html",
        minijinja::context!(user, posts, post_count, comment_count, commented_count, me),
    )
    .into_response())
}

#[derive(Deserialize)]
struct GetPostsParams {
    max_created_at: chrono::DateTime<chrono::Utc>,
}

async fn get_posts(
    session: Session,
    State(AppState { pool, .. }): State<AppState>,
    Query(params): Query<GetPostsParams>,
) -> Result<Response> {
    let mut conn = pool.acquire().await?;
    let results = sqlx::query_as::<_, Post>(
        "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM posts WHERE `created_at` <= ? ORDER BY `created_at` DESC"
    ).bind(params.max_created_at).fetch_all(&mut *conn).await?;

    let posts = make_posts(&mut conn, &results, get_csrf_token(&session).await, false).await?;

    if posts.is_empty() {
        return Ok(StatusCode::NOT_FOUND.into_response());
    }

    Ok(render_template("posts.html", minijinja::context!(posts)).into_response())
}

async fn get_posts_id(
    session: Session,
    Path(id): Path<i64>,
    State(AppState { pool, .. }): State<AppState>,
) -> Result<Response> {
    let mut conn = pool.acquire().await?;

    let resuls = sqlx::query_as::<_, Post>("SELECT * FROM posts WHERE `id` = ?")
        .bind(id)
        .fetch_all(&mut *conn)
        .await?;

    let posts = make_posts(&mut conn, &resuls, get_csrf_token(&session).await, true).await?;

    if posts.is_empty() {
        return Ok(StatusCode::NOT_FOUND.into_response());
    }

    let p = &posts[0];

    let me = get_session_user(&session, &mut conn).await?;

    Ok(render_template("post.html", minijinja::context!(me, post => p)).into_response())
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
        .route("/register", axum::routing::get(get_register))
        .route("/register", axum::routing::post(post_register))
        .route("/logout", axum::routing::get(get_logout))
        .route("/", axum::routing::get(get_index))
        .route("/posts", axum::routing::get(get_posts))
        .route("/posts/:id", axum::routing::get(get_posts_id))
        .route("/:account_name", axum::routing::get(get_account_name))
        .with_state(AppState { pool })
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .layer(session_layer)
        .fallback_service(serve_dir);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
