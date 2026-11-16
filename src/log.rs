//! One-line log messages on stderr, prefixed with the UTC time. The rc.d
//! script hands stderr to daemon(8), which passes it on to syslog.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Writes `HH:MM:SS.mmm keyhole: <message>`.
pub fn write(args: fmt::Arguments<'_>) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() % 86_400;
    eprintln!(
        "{:02}:{:02}:{:02}.{:03} keyhole: {args}",
        secs / 3600,
        secs / 60 % 60,
        secs % 60,
        now.subsec_millis()
    );
}

/// `log!("format", args...)`: see [`write`].
#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {
        $crate::log::write(format_args!($($arg)*))
    };
}
