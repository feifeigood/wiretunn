use std::{io, os::unix::io::AsRawFd};

use ipnet::IpNet;
use net_route::{Handle, Route};

use super::ifname_to_index;

/// Set platform specific route configuration
pub async fn set_route_configuration(
    ifname: String,
    routes: Vec<IpNet>,
    remove: bool,
) -> io::Result<()> {
    let ifindex = match ifname_to_index(&ifname) {
        Some(ifindex) => ifindex,
        None => return Err(io::Error::other("ifname_to_index fails")),
    };

    let handle = Handle::new()?;
    for route in routes {
        if remove {
            if let Err(e) = handle
                .delete(&Route::new(route.addr(), route.prefix_len()).with_ifindex(ifindex))
                .await
            {
                tracing::warn!(
                    "route delete {}/{} ifindex: {}, error: {}",
                    route.addr(),
                    route.prefix_len(),
                    ifindex,
                    e
                );
            }
        } else {
            if let Err(e) = handle
                .add(&Route::new(route.addr(), route.prefix_len()).with_ifindex(ifindex))
                .await
            {
                tracing::warn!(
                    "route add {}/{} ifindex: {}, error: {}",
                    route.addr(),
                    route.prefix_len(),
                    ifindex,
                    e
                );
            }
        }
    }

    Ok(())
}

/// Binds to a specific network interface (device)
pub fn set_bindtodevice<S: AsRawFd>(socket: &S, iface: &str) -> io::Result<()> {
    let iface_bytes = iface.as_bytes();

    unsafe {
        let ret = libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            iface_bytes.as_ptr() as *const _ as *const libc::c_void,
            iface_bytes.len() as libc::socklen_t,
        );

        if ret != 0 {
            let err = io::Error::last_os_error();
            tracing::error!("set SO_BINDTODEVICE error: {}", err);
            return Err(err);
        }
    }

    tracing::debug!("set SO_BINDTODEVICE ifname: {} success", iface);

    Ok(())
}
