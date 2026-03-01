use axum::{Router, response::Html, routing::get};
use std::fs;
use tracing_appender::non_blocking::WorkerGuard;

use tracing::{Level, info, warn};
use tracing_subscriber::{Registry, fmt, prelude::*};

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
    info!("log initialized successfully");
    let app = Router::new().route("/", get(hello_html));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

/* handler when user accesses the root path */
async fn hello_html() -> Html<String> {
    info!(target: "security", "Accessing the hello.html page"); // [3]
    // Read the HTML file into a string
    let contents =
        fs::read_to_string("templates/hello.html").expect("Should have been able to read the file"); // [4]
    // Return the string wrapped in the Html response type
    Html(contents) //sends html file to client.
}
