use std::io::{IsTerminal, Write};

pub fn init() {
    let color = std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn,scene=info"))
        .format(move |buf, record| {
            let (tag, shade) = match record.level() {
                log::Level::Error => ("fail", "\x1b[1;31m"),
                log::Level::Warn => ("warn", "\x1b[1;35m"),
                log::Level::Info if record.target() == "scene::done" => ("done", "\x1b[1;32m"),
                log::Level::Info => ("info", "\x1b[34m"),
                log::Level::Debug => ("debug", "\x1b[90m"),
                log::Level::Trace => ("trace", "\x1b[90m"),
            };
            let stamp = jiff::ZonedDateTime::now().strftime("%Y-%m-%d %H:%M:%S");
            if color {
                writeln!(buf, "[\x1b[90m{stamp}\x1b[0m] [{shade}{tag}\x1b[0m] {}", record.args())
            } else {
                writeln!(buf, "[{stamp}] [{tag}] {}", record.args())
            }
        })
        .init();
}
