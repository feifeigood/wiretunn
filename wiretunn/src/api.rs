use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use axum::{
    extract::{FromRef, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use boringtun::x25519::PublicKey;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::RwLock;

use crate::{
    device::{peer::AllowedIP, WgDevice},
    App,
};

pub fn router(app: &App) -> Router {
    let state = Arc::new(AppState {
        wg_device_state: WgDeviceState {
            devices: app.wg_devices.clone(),
        },
    });

    Router::new()
        .route(
            "/version",
            get(|| async {
                (
                    StatusCode::OK,
                    Json(json!({"version":env!("CARGO_PKG_VERSION")})),
                )
            }),
        )
        .route("/wg/:wg_name/peer", post(create_wg_peer))
        .with_state(state)
}

/// HTTPError is custom HTTP error for API
#[derive(Serialize)]
struct HTTPError {
    message: String,
}

impl HTTPError {
    pub fn new(message: &str) -> HTTPError {
        HTTPError {
            message: message.into(),
        }
    }
}

#[derive(Clone)]
struct AppState {
    wg_device_state: WgDeviceState,
}

#[derive(Clone)]
struct WgDeviceState {
    devices: Arc<RwLock<HashMap<String, WgDevice>>>,
}

impl FromRef<Arc<AppState>> for WgDeviceState {
    fn from_ref(app_state: &Arc<AppState>) -> Self {
        app_state.wg_device_state.clone()
    }
}

#[derive(Deserialize)]
struct WgPeer {
    #[serde(deserialize_with = "crate::config::deserialize::wg_public_key")]
    public_key: PublicKey,
    #[serde(
        default,
        deserialize_with = "crate::config::deserialize::wg_preshared_key"
    )]
    preshared_key: Option<[u8; 32]>,
    #[serde(deserialize_with = "crate::config::deserialize::wg_allowed_ips")]
    allowed_ips: Vec<IpNet>,
    persistent_keepalive: Option<u16>,
    #[serde(deserialize_with = "crate::config::deserialize::wg_endpoint")]
    endpoint: Option<SocketAddr>,
}

async fn create_wg_peer(
    State(wg_device): State<WgDeviceState>,
    Path(wg_name): Path<String>,
    Json(wg_peer): Json<WgPeer>,
) -> Response {
    match wg_device.devices.write().await.get_mut(&wg_name) {
        Some(device) => {
            let allowed_ips = wg_peer
                .allowed_ips
                .iter()
                .map(|x| AllowedIP::from(*x))
                .collect::<Vec<AllowedIP>>();

            // device
            //     .update_peer(
            //         wg_peer.public_key,
            //         false,
            //         false,
            //         wg_peer.endpoint,
            //         &allowed_ips,
            //         wg_peer.persistent_keepalive,
            //         wg_peer.preshared_key,
            //     )
            //     .await;

            StatusCode::NO_CONTENT.into_response()
        }
        None => (
            StatusCode::BAD_REQUEST,
            Json(HTTPError::new(&format!("can't find device: {}", wg_name))),
        )
            .into_response(),
    }
}
