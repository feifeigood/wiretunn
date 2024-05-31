use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

use device::WgDevice;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tun::TunBuilder;

use crate::config::Config;

mod api;
mod sys;

pub mod config;
pub mod device;
pub mod infra;
pub mod log;
pub mod rt;
pub mod signal;
pub mod tun;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("{0}")]
    Connect(String),
    #[error("tun2 error: {0}")]
    TunError(#[from] tun2::Error),
    #[error("toml error: {0}")]
    TomlError(#[from] toml::de::Error),
}

#[allow(unused)]
pub struct App {
    cfg: RwLock<Arc<Config>>,
    wg_devices: Arc<RwLock<HashMap<String, WgDevice>>>,

    guard: AppGuard,
    shutdown_token: CancellationToken,
}

impl App {
    fn new(conf: Option<PathBuf>) -> Result<App, Error> {
        Self::with_config(Config::load(conf)?)
    }

    pub fn with_config(config: Config) -> Result<App, Error> {
        let guard: AppGuard = {
            let log_guard = if !config.log_enabled() {
                None
            } else {
                Some(log::init_global_default(
                    config.log_file(),
                    config.log_level(),
                    None,
                    config.log_size(),
                    config.log_num(),
                    #[cfg(unix)]
                    None,
                    config.log_config().console.unwrap_or(true),
                ))
            };

            AppGuard { log_guard }
        };

        Ok(App {
            cfg: RwLock::new(Arc::new(config)),
            wg_devices: Default::default(),
            guard,
            shutdown_token: CancellationToken::new(),
        })
    }

    pub async fn run(&self) -> Result<(), Error> {
        self.create_wg_devices().await?;
        self.create_controller_apis().await?;

        self.wwait_until_exit().await
    }

    pub async fn shutdown(&self) {
        self.shutdown_token.cancel()
    }

    async fn wwait_until_exit(&self) -> Result<(), Error> {
        let signal = Box::pin(signal::shutdown());
        let shutdown = Box::pin(self.shutdown_token.cancelled());

        futures::future::select(signal, shutdown).await;
        {
            // close all wireguard device
            self.wg_devices
                .write()
                .await
                .iter()
                .for_each(|(_, device)| device.shutdown());
        }

        Ok(())
    }

    async fn create_wg_devices(&self) -> Result<(), Error> {
        let cfg = self.cfg.read().await.clone();
        let bind_iface = cfg.interface_name().to_owned();
        let wg_devices = self.wg_devices.clone();

        for (device_name, device_config) in cfg.wg_devices() {
            let mut tun_builder = TunBuilder::default();
            #[cfg(not(target_os = "macos"))]
            tun_builder.tun_name(&device_name);
            tun_builder.address(device_config.address);
            tun_builder.destination(device_config.address);
            // https://gist.github.com/nitred/f16850ca48c48c79bf422e90ee5b9d95#file-peer_mtu_vs_bandwidth-png
            tun_builder.mtu(device_config.mtu.unwrap_or(1420) as _);
            // for iOS/Android NE or VpnService
            #[cfg(unix)]
            if let Some(tun_fd) = device_config.tun_fd {
                tun_builder.file_descriptor(tun_fd);
                tun_builder.file_descriptor_close_on_drop(
                    device_config.tun_fd_close_on_drop.unwrap_or(true),
                );
            }

            let tun_device = tun_builder.build().await?;
            let mut routes = vec![];
            for peer in device_config.wg_peers.iter() {
                routes.extend_from_slice(&peer.allowed_ips);
            }

            _ = sys::set_route_configuration(tun_device.tun_name()?, routes, false).await;
            let wg_device = WgDevice::builder()
                .build(tun_device, device_config.clone(), bind_iface.to_owned())
                .await?;

            wg_devices
                .write()
                .await
                .insert(device_name.into(), wg_device);
        }

        Ok(())
    }

    async fn create_controller_apis(&self) -> Result<(), Error> {
        let cfg = self.cfg.read().await.clone();
        let shutdown_token = self.shutdown_token.clone();
        let api = api::router(self);

        if let Some(external_controller) = cfg.external_controller() {
            let listener = tokio::net::TcpListener::bind(external_controller).await?;
            tracing::info!(
                "Listening external controller apis on {}",
                listener.local_addr().unwrap()
            );

            tokio::spawn(async move {
                axum::serve(listener, api)
                    .with_graceful_shutdown(async move {
                        shutdown_token.cancelled().await;
                    })
                    .await
                    .expect("Failed to create controller api");
            });
        }

        Ok(())
    }
}

pub fn bootstrap(conf: Option<PathBuf>) -> Result<(), Error> {
    let app = Arc::new(App::new(conf)?);
    let runtime = crate::rt::build();
    let _g = runtime.enter();
    runtime.block_on(async move { app.run().await })?;
    runtime.shutdown_timeout(Duration::from_secs(5));
    Ok(())
}

#[allow(unused)]
struct AppGuard {
    log_guard: Option<tracing::dispatcher::DefaultGuard>,
}

/// Returns a version as specified in Cargo.toml
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
