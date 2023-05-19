use std::{fmt::{Display, Formatter}, fs::read_dir, net::{IpAddr, SocketAddr}, path::Path, sync::Arc};

use askama::Template;
use axum::{body::{Body, BoxBody, boxed}, extract::{DefaultBodyLimit, Multipart, State}, http::{Request, StatusCode}, response::{Html, IntoResponse, Response}, Router, routing::{get, post}, Server};
use base64::{Engine as _, engine::general_purpose};
use bytes::Bytes;
use chrono::{DateTime, Local};
use clap::Parser;
use humansize::{DECIMAL, format_size};
use percent_encoding::percent_decode;
use tower::ServiceExt;
use tower_http::{limit::RequestBodyLimitLayer, services::ServeDir, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Listen address
    #[arg(long, default_value = "127.0.0.1")]
    host: IpAddr,
    /// Port number
    #[arg(long, default_value = "8000")]
    http_port: u16,
    /// Root Directory
    #[arg(long, default_value = ".")]
    root: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let socket_address: SocketAddr = (args.host, args.http_port).into();
    let root = dunce::canonicalize(args.root).unwrap();

    let config = Arc::new(Args {
        host: args.host,
        http_port: args.http_port,
        root: root.to_str().unwrap().to_string(),
    });

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "beehive=debug,tower_http=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let app: _ = Router::new()
        .route("/favicon.ico", get(favicon))
        .route("/upload", post(upload))
        .layer(DefaultBodyLimit::disable())
        .layer(RequestBodyLimitLayer::new(1024 * 1024 * 1024)) /* 1Gb */
        .layer(TraceLayer::new_for_http())
        .fallback(handler)
        .with_state(config);

    tracing::debug!("Root directory: {}", root.display());
    tracing::debug!("Listening on {}", socket_address);
    Server::bind(&socket_address)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn upload(
    State(config): State<Arc<Args>>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, StatusCode> {
    let mut files: Vec<(String, Bytes)> = Vec::new();
    let mut path: String = "".to_string();
    let root = config.root.clone();
    while let Some(field) = multipart.next_field().await.unwrap() {
        let name = field.name().unwrap().to_string();

        if name.eq("path") {
            path = field.text().await.unwrap();
            continue;
        }

        let file_name = field.file_name().unwrap().to_string();
        let data = field.bytes().await.unwrap();
        files.push((file_name, data));
    }

    for (file_name, data) in files {
        let filepath = root.clone() + &path;
        let filepath = Path::new(&filepath);
        let filepath = filepath.join(Path::new(&file_name));
        tokio::fs::write(filepath, data).await.map_err(|e| {
            eprint!("Error writing file: {}", e);
        }).unwrap();
    }
    Ok(StatusCode::CREATED)
}

async fn handler(State(config): State<Arc<Args>>, request: Request<Body>) -> Result<Response<BoxBody>, (StatusCode, String)> {
    let path = percent_decode(request.uri().path().as_bytes()).decode_utf8().unwrap().to_string();
    let root = config.root.clone();
    return match ServeDir::new(&root).oneshot(request).await {
        Ok(response) => {
            match response.status() {
                StatusCode::NOT_FOUND => {
                    let path = root.clone() + path.as_str();
                    let path = Path::new(&path);
                    let paths = match read_dir(path) {
                        Ok(v) => v,
                        Err(error) => {
                            return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Invalid path, Error: {}", error)));
                        }
                    };
                    let mut file_list: Vec<FileInfo> = Vec::new();
                    let parent = path.parent().unwrap();
                    if !path.eq(Path::new(&root)) && parent.exists() {
                        let parent_metadata = parent.metadata().unwrap();
                        file_list.push(FileInfo {
                            name: "..".to_string(),
                            is_file: false,
                            last_modification: DateTime::from(parent_metadata.modified().unwrap()),
                            file_size: format_size(0u32, DECIMAL),
                        });
                    }
                    for entry in paths {
                        let entry = entry.unwrap();
                        let metadata = entry.metadata().unwrap();
                        file_list.push(FileInfo {
                            name: entry.file_name().into_string().unwrap(),
                            is_file: metadata.file_type().is_file(),
                            last_modification: DateTime::from(metadata.modified().unwrap()),
                            file_size: format_size(metadata.len(), DECIMAL),
                        });
                    }
                    Ok(FileListTemplate { files: file_list }.into_response())
                }
                _ => Ok(response.map(boxed))
            }
        }
        Err(err) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Something went wrong: {}", err),
        )),
    };
}

struct FileInfo {
    name: String,
    is_file: bool,
    last_modification: DateTime<Local>,
    file_size: String,
}

impl Display for FileInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

#[derive(Template)]
#[template(path = "files.html")]
struct FileListTemplate {
    files: Vec<FileInfo>,
}

impl IntoIterator for FileListTemplate {
    type Item = FileInfo;
    type IntoIter = std::vec::IntoIter<FileInfo>;

    fn into_iter(self) -> Self::IntoIter {
        self.files.into_iter()
    }
}

impl IntoResponse for FileListTemplate {
    fn into_response(self) -> Response<BoxBody> {
        match self.render() {
            Ok(html) => Html(html).into_response(),
            Err(error) => {
                (StatusCode::INTERNAL_SERVER_ERROR,
                 format!("Failed to render template. Error: {}", error)).into_response()
            }
        }
    }
}

//noinspection SpellCheckingInspection
async fn favicon() -> impl IntoResponse {
    let icon = concat!(
    "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQEAYAAABPYyMiAAAFT2lUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja",
    "2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4KPHg6eG1wbWV0YSB4bWxuczp4PSJhZG",
    "9iZTpuczptZXRhLyIgeDp4bXB0az0iWE1QIENvcmUgNS41LjAiPgogPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d",
    "3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4KICA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIgog",
    "ICAgeG1sbnM6ZGM9Imh0dHA6Ly9wdXJsLm9yZy9kYy9lbGVtZW50cy8xLjEvIgogICAgeG1sbnM6ZXhpZj0iaHR0cDovL",
    "25zLmFkb2JlLmNvbS9leGlmLzEuMC8iCiAgICB4bWxuczp0aWZmPSJodHRwOi8vbnMuYWRvYmUuY29tL3RpZmYvMS4wLy",
    "IKICAgIHhtbG5zOnBob3Rvc2hvcD0iaHR0cDovL25zLmFkb2JlLmNvbS9waG90b3Nob3AvMS4wLyIKICAgIHhtbG5zOnh",
    "tcD0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wLyIKICAgIHhtbG5zOnhtcE1NPSJodHRwOi8vbnMuYWRvYmUuY29t",
    "L3hhcC8xLjAvbW0vIgogICAgeG1sbnM6c3RFdnQ9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9SZXNvd",
    "XJjZUV2ZW50IyIKICAgZXhpZjpQaXhlbFhEaW1lbnNpb249IjE2IgogICBleGlmOlBpeGVsWURpbWVuc2lvbj0iMTYiCi",
    "AgIGV4aWY6Q29sb3JTcGFjZT0iNjU1MzUiCiAgIHRpZmY6SW1hZ2VXaWR0aD0iMTYiCiAgIHRpZmY6SW1hZ2VMZW5ndGg",
    "9IjE2IgogICB0aWZmOlJlc29sdXRpb25Vbml0PSIyIgogICB0aWZmOlhSZXNvbHV0aW9uPSIzMDAvMSIKICAgdGlmZjpZ",
    "UmVzb2x1dGlvbj0iMzAwLzEiCiAgIHBob3Rvc2hvcDpDb2xvck1vZGU9IjMiCiAgIHBob3Rvc2hvcDpJQ0NQcm9maWxlP",
    "SJEaXNwbGF5IFAzIgogICB4bXA6TW9kaWZ5RGF0ZT0iMjAyMi0wNy0zMVQyMTozOToxNSswOTowMCIKICAgeG1wOk1ldG",
    "FkYXRhRGF0ZT0iMjAyMi0wNy0zMVQyMTozOToxNSswOTowMCI+CiAgIDxkYzp0aXRsZT4KICAgIDxyZGY6QWx0PgogICA",
    "gIDxyZGY6bGkgeG1sOmxhbmc9IngtZGVmYXVsdCI+YmVlaGl2ZTwvcmRmOmxpPgogICAgPC9yZGY6QWx0PgogICA8L2Rj",
    "OnRpdGxlPgogICA8eG1wTU06SGlzdG9yeT4KICAgIDxyZGY6U2VxPgogICAgIDxyZGY6bGkKICAgICAgc3RFdnQ6YWN0a",
    "W9uPSJwcm9kdWNlZCIKICAgICAgc3RFdnQ6c29mdHdhcmVBZ2VudD0iQWZmaW5pdHkgRGVzaWduZXIgMS4xMC41IgogIC",
    "AgICBzdEV2dDp3aGVuPSIyMDIyLTA3LTMxVDIxOjM5OjE1KzA5OjAwIi8+CiAgICA8L3JkZjpTZXE+CiAgIDwveG1wTU0",
    "6SGlzdG9yeT4KICA8L3JkZjpEZXNjcmlwdGlvbj4KIDwvcmRmOlJERj4KPC94OnhtcG1ldGE+Cjw/eHBhY2tldCBlbmQ9",
    "InIiPz6TAW7eAAABaWlDQ1BEaXNwbGF5IFAzAAAokXWQvUvDUBTFT6tS0DqIDh0cMolD1NIKdnFoKxRFMFQFq1P6+iU0M",
    "SQpUnETVyn4H1jBWXCwiFRwcXAQRAcR3Zw6Kbhoed6XVNoi3sfl/Ticc7lcwBsoMs3qBaDptplMxKS11Lrke4OHnlMqs4",
    "yooiwK/v276/PR9d5PiFmNZvUgsp+41s4ul3aeAlN//V3Vn8lajP5v6iAzTBvwyMTKtm0I3iUeMWkp4orgvMvHgtMunzu",
    "elWSc+JZYYgU1Q9wgltMder6DtWKJtXYQ2/uz+uqymEM9ijlswoKBIlSUIUFB+B//tOOPY4vcZZiUy6MAmzJRUsSELPE8",
    "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",
    "AAAASUVORK5CYII=",
    );
    (
        axum::response::AppendHeaders([
            (axum::http::header::CONTENT_TYPE, "image/vnd.microsoft.icon"),
        ]),
        general_purpose::STANDARD.decode(icon).unwrap(),
    )
}