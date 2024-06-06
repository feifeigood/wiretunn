// Requiring explicit per-fn "Safety" docs not worth it. Just pass in valid
// pointers and buffers/lengths to these, ok?
#![allow(clippy::missing_safety_doc)]

//! C bindings for the Wiretunn Library

use std::{
    collections::HashMap,
    ffi::{c_char, CStr, CString},
    mem, ptr,
    sync::Arc,
};

use futures::future::Either;
use parking_lot::Mutex;
use tokio::{runtime::Runtime, sync::mpsc};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use wiretunn::{config::Config, log, rt, App};

lazy_static::lazy_static! {
     static ref RUNTIME_MANAGER: Mutex<HashMap<u8, mpsc::Sender<u8>>> = Mutex::new(HashMap::new());
}

/// Return FFI library version
#[no_mangle]
pub extern "C" fn wiretunn_version() -> *mut c_char {
    CString::new(wiretunn::version()).unwrap().into_raw()
}

/// Create and run a new Wiretunn App, this function will blocks current thread.
#[no_mangle]
pub unsafe extern "C" fn wiretunn_app_run(runtime_id: u8, s: *const c_char) -> i32 {
    // Init log
    log::default(tracing::Level::DEBUG);

    let config_str = match unsafe { CStr::from_ptr(s) }.to_str() {
        Ok(string) => string,
        Err(e) => {
            tracing::error!("Parse config error: {:?}", e);
            return exitcode::CONFIG;
        }
    };

    tracing::info!("{}", config_str);

    let config = match Config::load_from_str(config_str) {
        Ok(config) => config,
        Err(e) => {
            tracing::error!("Parse config error: {:?}", e);
            return exitcode::CONFIG;
        }
    };

    // Create Wiretunn App
    let app = Arc::new(match App::with_config(config) {
        Ok(app) => app,
        Err(e) => {
            tracing::error!("Create Wiretunn app error: {:?}", e);
            return exitcode::UNAVAILABLE;
        }
    });

    let (tx, mut rx) = mpsc::channel::<u8>(1);

    RUNTIME_MANAGER.lock().insert(runtime_id, tx);

    let rt = rt::build();
    let _g = rt.enter();
    if let Err(e) = rt.block_on(async move {
        let tunnel = Box::pin(app.run());
        let rx = Box::pin(rx.recv());
        match futures::future::select(tunnel, rx).await {
            // Tunnel future resolved without an error. This should never happen.
            Either::Left((Ok(..), ..)) => unreachable!(),
            Either::Left((Err(e), ..)) => Err(e),
            Either::Right(_) => Ok(()),
        }
    }) {
        tracing::error!("Running Wiretunn app error: {:?}", e);
        return exitcode::IOERR;
    }

    rt.shutdown_background();
    RUNTIME_MANAGER.lock().remove(&runtime_id);

    exitcode::OK
}

/// Notify the Wiretunn App shutdown
#[no_mangle]
pub unsafe extern "C" fn wiretunn_app_shutdown(runtime_id: u8) {
    if let Err(e) = RUNTIME_MANAGER
        .lock()
        .get(&runtime_id)
        .expect("shutdown wiretunn app fails")
        .blocking_send(0)
    {
        tracing::error!("{:?}", e);
    };
}

lazy_static::lazy_static! {
    static ref RUNTIME: Mutex<Runtime> = Mutex::new(rt::build());
}

pub struct ShutdownHandle {
    tracker: TaskTracker,
    shutdown_token: CancellationToken,
}

/// Allocate a new tunnel, return NULL on failure.
#[no_mangle]
pub unsafe extern "C" fn new_tunnel(s: *const c_char) -> *mut tokio::sync::Mutex<ShutdownHandle> {
    // Init log
    log::default(tracing::Level::DEBUG);

    let config_str = match unsafe { CStr::from_ptr(s) }.to_str() {
        Ok(string) => string,
        Err(e) => {
            tracing::error!("Parse config error: {:?}", e);
            return ptr::null_mut();
        }
    };

    tracing::info!("{}", config_str);

    let config = match Config::load_from_str(config_str) {
        Ok(config) => config,
        Err(e) => {
            tracing::error!("Parse config error: {:?}", e);
            return ptr::null_mut();
        }
    };

    // Create Wiretunn App
    let app = Arc::new(match App::with_config(config) {
        Ok(app) => app,
        Err(e) => {
            tracing::error!("Create Wiretunn app error: {:?}", e);
            return ptr::null_mut();
        }
    });

    let rt = RUNTIME.lock();
    let _g = rt.enter();
    let shutdown_handle = rt.block_on(async move {
        let tracker = TaskTracker::new();
        let shutdown_token = CancellationToken::new();

        let shutdown_token_cloned = shutdown_token.clone();
        tracker.spawn(async move {
            let tunnel = Box::pin(app.run());
            let shutdown_token = shutdown_token_cloned.clone();
            let shutdown = Box::pin(shutdown_token.cancelled());

            let _ = match futures::future::select(tunnel, shutdown).await {
                // Tunnel future resolved without an error. This should never happen.
                Either::Left((Ok(..), ..)) => unreachable!(),
                Either::Left((Err(e), ..)) => Err(e),
                Either::Right(_) => Ok(()),
            };

            tracing::info!("Wiretunn {} shutdown", wiretunn::version());
        });

        Box::new(tokio::sync::Mutex::new(ShutdownHandle {
            tracker,
            shutdown_token,
        }))
    });

    Box::into_raw(shutdown_handle)
}

/// Drops the Tunnel object
#[no_mangle]
pub unsafe extern "C" fn tunnel_free(shutdown_handle: *mut tokio::sync::Mutex<ShutdownHandle>) {
    let mut rt = RUNTIME.lock();
    rt.block_on(async move {
        let shutdown_handle = Box::from_raw(shutdown_handle);
        shutdown_handle.lock().await.tracker.close();
        shutdown_handle.lock().await.shutdown_token.cancel();
        // Wait for all tasks to exit.
        shutdown_handle.lock().await.tracker.wait().await;

        drop(shutdown_handle)
    });

    // Drop previous runtime
    let prev_rt = mem::replace(&mut *rt, rt::build());
    prev_rt.shutdown_background();
}

/// Subtracting the "disallowed" IP address blocks from the "allowed" IP address blocks
#[no_mangle]
pub unsafe extern "C" fn split_disallowed_ips(
    allowed_ips: *const c_char,
    disallowed_ips: *const c_char,
) -> *mut c_char {
    use ipnet::IpNet;

    let (allowed_ips, disallowed_ips) =
        unsafe { (CStr::from_ptr(allowed_ips), CStr::from_ptr(disallowed_ips)) };

    if let (Ok(allowed_ips), Ok(disallowed_ips)) = (allowed_ips.to_str(), disallowed_ips.to_str()) {
        let allowed_ips = allowed_ips
            .split(',')
            .into_iter()
            .filter_map(|ipnet| ipnet.parse::<IpNet>().ok())
            .collect::<Vec<IpNet>>();

        let disallowed_ips = disallowed_ips
            .split(',')
            .into_iter()
            .filter_map(|ipnet| ipnet.parse::<IpNet>().ok())
            .collect::<Vec<IpNet>>();

        if !allowed_ips.is_empty() && !disallowed_ips.is_empty() {
            let calculated_allowed_ips =
                wiretunn::device::split_disallowed_ips(&allowed_ips, &disallowed_ips);
            if !calculated_allowed_ips.is_empty() {
                return CString::new(
                    calculated_allowed_ips
                        .iter()
                        .map(|x| format!("{}", x))
                        .collect::<Vec<String>>()
                        .join(","),
                )
                .unwrap()
                .into_raw();
            }
        }
    } else {
        eprintln!("Couldn't convert allowed_ips/disallowed_ips to CStr");
    }

    ptr::null_mut()
}
