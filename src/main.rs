use std::fmt::{Display, Formatter};
use askama::Template;
use std::fs::read_dir;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use axum::{Router, Server};
use axum::body::{Body, BoxBody, boxed};
use axum::http::{Request, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use chrono::{DateTime, Local};
use clap::Parser;
use tower::ServiceExt;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;


#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Listen address
    #[clap(long, default_value = "127.0.0.1")]
    host: IpAddr,
    /// Port number
    #[clap(long, default_value = "8000")]
    http_port: u16,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let socket_address: SocketAddr = (args.host, args.http_port).into();

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "beehive=debug,tower_http=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let app: _ = Router::new()
        .fallback(get(handle))
        .layer(TraceLayer::new_for_http());

    tracing::debug!("Listening on {}", socket_address);
    Server::bind(&socket_address)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn handle(request: Request<Body>) -> Result<Response<BoxBody>, (StatusCode, String)> {
    let path = request.uri().path().to_string();
    return match ServeDir::new(".").oneshot(request).await {
        Ok(response) => {
            match response.status() {
                StatusCode::NOT_FOUND => {
                    let path = ".".to_string() + path.as_str();
                    let path = Path::new(&path);
                    let paths = match read_dir(path) {
                        Ok(v) => v,
                        Err(error) => {
                            return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Invalid path, Error: {}", error)));
                        }
                    };
                    let mut file_list: Vec<FileInfo> = Vec::new();
                    let parent = path.parent().unwrap();
                    if parent.exists() {
                        let parent_metadata = parent.metadata().unwrap();
                        file_list.push(FileInfo {
                            name: "..".to_string(),
                            is_file: false,
                            last_modification: DateTime::from(parent_metadata.modified().unwrap()),
                        });
                    }
                    for entry in paths {
                        let entry = entry.unwrap();
                        let metadata = entry.metadata().unwrap();
                        file_list.push(FileInfo {
                            name: entry.file_name().into_string().unwrap(),
                            is_file: metadata.file_type().is_file(),
                            last_modification: DateTime::from(metadata.modified().unwrap()),
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