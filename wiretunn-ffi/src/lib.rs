// Requiring explicit per-fn "Safety" docs not worth it. Just pass in valid
// pointers and buffers/lengths to these, ok?
#![allow(clippy::missing_safety_doc)]

//! C bindings for the Wiretunn Library

use std::{
    collections::HashMap,
    ffi::{c_char, CStr, CString},
    sync::Arc,
};

use futures::future::Either;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use wiretunn::{config::Config, rt, App};

lazy_static::lazy_static! {
     static ref RUNTIME_MANAGER: Mutex<HashMap<u8, mpsc::Sender<u8>>> = Mutex::new(HashMap::new());
}

/// Return FFI library version
#[no_mangle]
pub extern "C" fn wiretunn_version() -> *mut c_char {
    CString::new(env!("CARGO_PKG_VERSION")).unwrap().into_raw()
}

/// Create and run a new Wiretunn App, this function will blocks current thread.
#[no_mangle]
pub unsafe extern "C" fn wiretunn_app_run(runtime_id: u8, s: *const c_char) -> i32 {
    let config_str = match unsafe { CStr::from_ptr(s) }.to_str() {
        Ok(string) => string,
        Err(_) => {
            return exitcode::CONFIG;
        }
    };

    println!("{}", config_str);

    let config = match Config::load_from_str(config_str) {
        Ok(config) => config,
        Err(_) => {
            return exitcode::CONFIG;
        }
    };

    // Create Wiretunn App
    let app = Arc::new(match App::with_config(config) {
        Ok(app) => app,
        Err(_) => {
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
        eprintln!("running wiretunn app error {:?}", e);
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
        eprintln!("{:?}", e);
    };
}
