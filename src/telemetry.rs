// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
use once_cell::sync::Lazy;
use once_cell::sync::OnceCell;
use std::time::Instant;
use tracing::warn;
use tracing_subscriber::{
    filter,
    filter::{EnvFilter, LevelFilter},
    prelude::*,
    reload, Layer, Registry,
};
use tracing_subscriber::{fmt, EnvFilter, Layer, Registry};

pub static APPLICATION_START_TIME: Lazy<Instant> = Lazy::new(Instant::now);
static LOG_HANDLE: OnceCell<LogHandle> = OnceCell::new();

#[cfg(feature = "console")]
pub fn setup_logging() {
    Lazy::force(&APPLICATION_START_TIME);
    tracing_subscriber::registry()
        .with(console_subscriber::spawn())
        .with(fmt_layer())
        .init();
}

#[cfg(not(feature = "console"))]
pub fn setup_logging() {
    Lazy::force(&APPLICATION_START_TIME);
    tracing_subscriber::registry().with(fmt_layer()).init();
}

fn fmt_layer() -> impl Layer<Registry> + Sized {
    let format = fmt::format();
    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();
    let (filter_layer, reload_handle) =
        reload::Layer::new(tracing_subscriber::fmt::layer().with_filter(filter));
    LOG_HANDLE
        .set(LogHandle {
            handle: reload_handle,
        })
        .map_or_else(|_| warn!("setup log handler failed"), |_| {});
    tracing_subscriber::registry().with(filter_layer).init();
}

// a handle to get and set the log level
type BoxLayer = tracing_subscriber::fmt::Layer<tracing_subscriber::Registry>;
type FilteredLayer = filter::Filtered<BoxLayer, EnvFilter, Registry>;
struct LogHandle {
    handle: reload::Handle<FilteredLayer, Registry>,
}

pub fn set_global_level(level: LevelFilter) -> bool {
    if let Some(static_log_handler) = LOG_HANDLE.get() {
        let filter = tracing_subscriber::EnvFilter::from_default_env().add_directive(level.into());
        static_log_handler
            .handle
            .modify(|layer| {
                *layer.filter_mut() = filter;
            })
            .map_or(false, |_| true)
    } else {
        warn!("failed to get log handle");
        false
    }
}

pub fn get_current_loglevel() -> Option<String> {
    if let Some(static_log_handler) = LOG_HANDLE.get() {
        static_log_handler
            .handle
            .with_current(|f| format!("{}", f.filter()))
            .ok()
    } else {
        warn!("failed to get log handle");
        None
    }
}

pub fn get_log_level_from_str(level_str: String) -> Option<LevelFilter> {
    match level_str.as_str() {
        "debug" => Some(LevelFilter::DEBUG),
        "error" => Some(LevelFilter::ERROR),
        "info" => Some(LevelFilter::INFO),
        "warn" => Some(LevelFilter::WARN),
        "trace" => Some(LevelFilter::TRACE),
        "off" => Some(LevelFilter::OFF),
        _ => {
            warn!("unable to find newlevel in request {}", level_str);
            None
        }
    }
}
