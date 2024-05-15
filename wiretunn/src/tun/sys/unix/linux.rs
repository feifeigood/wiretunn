use std::io;

use ipnet::IpNet;
use net_route::{Handle, Route};

use super::ifname_to_index;

/// Set platform specific route configuration
pub async fn set_route_configuration(ifname: String, routes: Vec<IpNet>) -> io::Result<()> {
    let ifindex = match ifname_to_index(&ifname) {
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
