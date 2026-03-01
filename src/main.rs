use axum::{Router, response::Html, routing::get};
use tracing_appender::non_blocking::WorkerGuard;

use tracing::{error, info}; //add Level and warn if needed
use tracing_subscriber::{fmt, prelude::*}; //add Registry if needed

fn init_log() -> (WorkerGuard, WorkerGuard) {
    /* configure general logs */
    let general_file_appender = tracing_appender::rolling::never("./logs", "general.log");
    let (general_writer, guard1) = tracing_appender::non_blocking(general_file_appender);

    let general_layer = fmt::layer().with_writer(general_writer).with_filter(
        tracing_subscriber::filter::filter_fn(|metadata| metadata.target() != "security"),
    );

    /* configure security logs */
    let security_file_appender = tracing_appender::rolling::never("./logs", "security.log");
    let (security_writer, guard2) = tracing_appender::non_blocking(security_file_appender);

    let security_layer = fmt::layer().with_writer(security_writer).with_filter(
        tracing_subscriber::filter::filter_fn(|metadata| metadata.target() == "security"),
    );

    /* register both layers in one subscriber */
    tracing_subscriber::registry()
        .with(general_layer)
        .with(security_layer)
        .init();

    (guard1, guard2)
}

#[tokio::main]
async fn main() {
    let (_guard1, _guard2) = init_log();
    info!("general log initialized successfully");
    info!(target: "security", "security log initialized");
    let app = Router::new().route("/", get(hello_html));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await;
    let listener = match listener {
        Ok(listener) => listener,
        Err(e) => {
            error!("Failed to bind to port 3000: {}", e);
            panic!("error occurred: read logs/general.log or security.log for more details: {}", e);
        }
    };
    let axum_result = axum::serve(listener, app).await;
    if let Err(e) = axum_result {
        error!("Server error: {}", e);
        panic!("error occurred: read logs/general.log or security.log for more details: {}", e);
    }
}

/* handler when user accesses the root path (ex: http://localhost:3000/) */
async fn hello_html() -> Html<String> {
    info!("Serving hello.html to client");
    let contents = include_str!("../templates/hello.html").to_string(); //reads the html file and converts it to a string.
    /* send content of templates/hello.html back to client */
    Html(contents)
}