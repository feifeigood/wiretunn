use std::{collections::HashMap, fs, path::PathBuf};

use anyhow::Context;
use clap::{command, Parser};
use serde::Deserialize;

use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{error, info, Level};
use wiretunn::{
    device::{WgDevice, WgDeviceConfig},
    signal,
};

#[derive(Parser)]
#[command(version, about)]
pub struct Opts {
    /// Sets a custom config file
    #[arg(short, long, value_name = "FILE")]
    config: PathBuf,

    #[arg(
        long,
        value_name = "LOG_LEVEL",
        default_value_t = Level::ERROR
    )]
    log_level: Level,
}

#[derive(Deserialize)]
pub struct Config {
    #[serde(rename = "wireguard")]
    pub wg_devices: HashMap<String, WgDeviceConfig>,
}

impl Config {
    pub fn load_from_file(path: &PathBuf) -> anyhow::Result<Config> {
        let config_contents = fs::read_to_string(path)
            .with_context(|| format!("Can't open config file: {}", path.as_path().display()))?;

        let config = toml::from_str(&config_contents)?;
        Ok(config)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();

    tracing_subscriber::fmt()
        .with_max_level(opts.log_level)
        .init();

    let config = Config::load_from_file(&opts.config)?;
    let tracker = TaskTracker::new();
    let shutdown_token = CancellationToken::new();

    for (name, config) in config.wg_devices {
        let mut wg_device = WgDevice::builder().name(&name).build(config).await?;
        let shutdown_token = shutdown_token.clone();
        tracker.spawn(async move {
            tokio::select! {
                res = wg_device.wait_until_exit() => {
                    if let Err(err) = res {
                        error!("WireGuard {} error {}", wg_device.name(), err);
                    }
                }
                _ = shutdown_token.cancelled() => {
                    info!("WireGuard {} shutdown", wg_device.name());
                    wg_device.shutdown_gracefully().await;
                }
            }
        });
    }

    let _ = signal::shutdown().await;
    shutdown_token.cancel();
    tracker.close();
    // Wait for all tasks to exit.
    tracker.wait().await;

    Ok(())
}
