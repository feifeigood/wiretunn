use std::{io, net::IpAddr, process::Command, time::Duration};

use ipnet::IpNet;
use net_route::{Handle, Route};
use tracing::warn;

/// Set platform specific route configuration
pub async fn set_route_configuration(ifname: String, routes: Vec<IpNet>) -> io::Result<()> {
    for route in routes {
        let mut binding = Command::new("netsh");
        let mut cmd = binding
            .arg("interface")
            .arg(if route.addr().is_ipv4() {
                "ipv4"
            } else {
                "ipv6"
            })
            .arg("add")
            .arg("route")
            .arg(format!("{}/{}", route.addr(), route.prefix_len()).as_str())
            .arg(format!("{}", ifname).as_str())
            .arg("store=active");

        tracing::debug!("{}", format!("{:?}", cmd).replace("\"", ""));
        if let Err(e) = cmd.output() {
            warn!(message = "netsh add route error", error=?e);
        }
    }

    Ok(())
}

pub fn deterministic_guid(ifname: &str) -> Option<u128> {
    use blake2::{Blake2s256, Digest};
    use byteorder::{ByteOrder, LittleEndian};
    use bytes::{BufMut, BytesMut};
    use unicode_normalization::UnicodeNormalization;

    // https://github.com/WireGuard/wireguard-windows/blob/master/tunnel/deterministicguid.go
    let mut data = BytesMut::from("Fixed WireGuard Windows GUID v1 jason@zx2c4.com");
    let b2str = ifname.nfc().map(|c| c as u8).collect::<Vec<u8>>();
    let mut b2num = [0u8; 4];
    LittleEndian::write_u32(&mut b2num, b2str.len() as u32);
    data.put_slice(&b2num[..]);
    data.put_slice(&b2str[..]);

    let mut buf = [0u8; 16];
    buf.copy_from_slice(&Blake2s256::digest(&data[..])[..16]);

    Some(u128::from_le_bytes(buf))
}
