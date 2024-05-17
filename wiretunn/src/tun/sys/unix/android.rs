use std::io;

use ipnet::IpNet;

/// Set platform specific route configuration
pub async fn set_route_configuration(
    _ifname: String,
    _routes: Vec<IpNet>,
    remove: bool,
) -> io::Result<()> {
    Ok(())
}
