use std::{
    io::{self, ErrorKind},
    mem,
    net::SocketAddr,
    os::unix::io::AsRawFd,
    ptr,
};

use ipnet::IpNet;
use net_route::{Handle, Route};

/// Set platform specific route configuration
pub async fn set_route_configuration(
    ifname: String,
    routes: Vec<IpNet>,
    remove: bool,
) -> io::Result<()> {
    let ifindex = match net_route::ifname_to_index(&ifname) {
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
        } else if let Err(e) = handle
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

    Ok(())
}

/// Binds to a specific network interface (device)
pub fn set_ip_bound_if<S: AsRawFd>(socket: &S, addr: &SocketAddr, iface: &str) -> io::Result<()> {
    const IP_BOUND_IF: libc::c_int = 25; // bsd/netinet/in.h
    const IPV6_BOUND_IF: libc::c_int = 125; // bsd/netinet6/in6.h

    let index = unsafe {
        let mut ciface = [0u8; libc::IFNAMSIZ];
        if iface.len() >= ciface.len() {
            return Err(ErrorKind::InvalidInput.into());
        }

        let iface_bytes = iface.as_bytes();
        ptr::copy_nonoverlapping(iface_bytes.as_ptr(), ciface.as_mut_ptr(), iface_bytes.len());

        libc::if_nametoindex(ciface.as_ptr() as *const libc::c_char)
    };

    if index == 0 {
        let err = io::Error::last_os_error();
        tracing::error!("if_nametoindex ifname: {} error: {}", iface, err);
        return Err(err);
    }

    unsafe {
        let ret = match addr {
            SocketAddr::V4(..) => libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                IP_BOUND_IF,
                &index as *const _ as *const _,
                mem::size_of_val(&index) as libc::socklen_t,
            ),
            SocketAddr::V6(..) => libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                IPV6_BOUND_IF,
                &index as *const _ as *const _,
                mem::size_of_val(&index) as libc::socklen_t,
            ),
        };

        if ret < 0 {
            let err = io::Error::last_os_error();
            tracing::error!(
                "set IF_BOUND_IF/IPV6_BOUND_IF ifname: {} ifindex: {} error: {}",
                iface,
                index,
                err
            );
            return Err(err);
        }
    }

    tracing::debug!(
        "set {} ifname: {} ifindex:{} success",
        match addr {
            SocketAddr::V4(..) => "IF_BOUND_IF",
            SocketAddr::V6(..) => "IPV6_BOUND_IF",
        },
        iface,
        index,
    );

    Ok(())
}
