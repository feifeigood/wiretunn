use std::io;

use ipnet::IpNet;

use crate::tun::Tun;

/// Set platform specific route configuration
pub async fn set_route_configuration(_tun_device: &mut Tun, _routes: Vec<IpNet>) -> io::Result<()> {
    Ok(())
}
