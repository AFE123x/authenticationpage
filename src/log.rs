use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{Layer, fmt, layer::SubscriberExt, util::SubscriberInitExt};

pub fn init_log() -> (WorkerGuard, WorkerGuard, WorkerGuard) {
    /* configure general logs */
    let general_file_appender = tracing_appender::rolling::never("./logs", "general.log");
    let (general_writer, guard1) = tracing_appender::non_blocking(general_file_appender);

    let general_layer = fmt::layer().with_writer(general_writer).with_filter(
        tracing_subscriber::filter::filter_fn(|metadata| {
            metadata.target() != "security" && metadata.target() != "access"
        }),
    );

    /* configure security logs */
    let security_file_appender = tracing_appender::rolling::never("./logs", "security.log");
    let (security_writer, guard2) = tracing_appender::non_blocking(security_file_appender);

    let security_layer = fmt::layer().with_writer(security_writer).with_filter(
        tracing_subscriber::filter::filter_fn(|metadata| metadata.target() == "security"),
    );

    /* configure access logs (audit trail) */
    let access_file_appender = tracing_appender::rolling::never("./logs", "access.log");
    let (access_writer, guard3) = tracing_appender::non_blocking(access_file_appender);

    let access_layer = fmt::layer()
        .with_target(false)
        .with_ansi(false)
        .with_writer(access_writer)
        .with_filter(tracing_subscriber::filter::filter_fn(|metadata| {
            metadata.target() == "access"
        }));

    /* register all layers in one subscriber */
    tracing_subscriber::registry()
        .with(general_layer)
        .with(security_layer)
        .with(access_layer)
        .init();

    (guard1, guard2, guard3)
}
