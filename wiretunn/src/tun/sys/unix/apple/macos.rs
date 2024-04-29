use std::io;

use ipnet::IpNet;
use net_route::{Handle, Route};

use crate::tun::Tun;

/// Set platform specific route configuration
pub async fn set_route_configuration(tun_device: &mut Tun, routes: Vec<IpNet>) -> io::Result<()> {
    let ifindex = net_route::ifname_to_index(
        &tun_device
            .tun_name()
            .map_err(|e| io::Error::other(e.to_string()))?,
    );

    let ifindex = match ifindex {
        Some(ifindex) => ifindex,
        None => return Err(io::Error::other("ifname_to_index fails")),
    };

    let handle = Handle::new()?;

    for route in routes {
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

    Ok(())
}
