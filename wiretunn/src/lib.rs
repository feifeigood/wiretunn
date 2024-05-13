use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

use device::WgDevice;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tun::TunBuilder;

use crate::config::Config;

mod api;
mod rt;

pub mod config;
pub mod device;
pub mod infra;
pub mod log;
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

pub struct App {
    cfg: RwLock<Arc<Config>>,
    wg_interfaces: Arc<RwLock<HashMap<String, WgDevice>>>,
    guard: AppGuard,
    shutdown_token: CancellationToken,
}

impl App {
    fn new(conf: Option<PathBuf>) -> Result<App, Error> {
        let config = Config::load(conf)?;

        let guard = {
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
                    config.log_config().console.unwrap_or_default(),
                ))
            };

            AppGuard { log_guard }
        };

        Ok(App {
            cfg: RwLock::new(Arc::new(config)),
            wg_interfaces: Default::default(),
            guard,
            shutdown_token: CancellationToken::new(),
        })
    }
}

pub fn bootstrap(conf: Option<PathBuf>) -> Result<(), Error> {
    let app = Arc::new(App::new(conf)?);

    let runtime = crate::rt::build();
    let _guard = runtime.enter();

    runtime.block_on(async {
        create_wg_devices(&app).await?;
        create_controller_apis(&app).await?;
        Ok::<_, Error>(())
    })?;

    runtime.block_on(async move {
        signal::shutdown().await;

        // close all wireguard device
        app.wg_interfaces
            .write()
            .await
            .iter()
            .for_each(|(_, device)| device.shutdown());
    });

    runtime.shutdown_timeout(Duration::from_secs(5));

    Ok(())
}

async fn create_wg_devices(app: &Arc<App>) -> Result<(), Error> {
    let cfg = app.cfg.read().await.clone();

    let wg_interfaces = app.wg_interfaces.clone();

    for (device_name, device_config) in cfg.wg_devices() {
        let mut tun_builder = TunBuilder::default();
        #[cfg(not(target_os = "macos"))]
        tun_builder.tun_name(&device_name);
        tun_builder.address(device_config.address);
        tun_builder.destination(device_config.address);
        // https://gist.github.com/nitred/f16850ca48c48c79bf422e90ee5b9d95#file-peer_mtu_vs_bandwidth-png
        tun_builder.mtu(device_config.mtu.unwrap_or(1420) as _);

        let mut tun_device = tun_builder.build().await?;
        let mut routes = vec![];
        for peer in device_config.wg_peers.iter() {
            routes.extend_from_slice(&peer.allowed_ips);
        }

        _ = tun::set_route_configuration(&mut tun_device, routes).await;
        let wg_device = WgDevice::builder()
            .build(tun_device, device_config.clone())
            .await?;

        wg_interfaces
            .write()
            .await
            .insert(device_name.into(), wg_device);
    }

    Ok(())
}

async fn create_controller_apis(app: &Arc<App>) -> Result<(), Error> {
    let cfg = app.cfg.read().await.clone();
    let shutdown_token = app.shutdown_token.clone();

    if let Some(external_controller) = cfg.external_controller() {
        let listener = tokio::net::TcpListener::bind(external_controller).await?;
        tracing::info!(
            "Listening external controller apis on {}",
            listener.local_addr().unwrap()
        );

        tokio::spawn(async move {
            axum::serve(listener, api::router())
                .with_graceful_shutdown(async move {
                    shutdown_token.cancelled().await;
                })
                .await
                .expect("Failed to create controller api");
        });
    }

    Ok(())
}
struct AppGuard {
    log_guard: Option<tracing::dispatcher::DefaultGuard>,
}
