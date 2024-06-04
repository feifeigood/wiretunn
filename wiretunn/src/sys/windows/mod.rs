use std::{
    ffi::{CStr, CString, OsString},
    io::{self, ErrorKind},
    mem,
    net::{IpAddr, SocketAddr},
    os::windows::{ffi::OsStringExt, io::AsRawSocket},
    process::Command,
    ptr, slice,
    time::Duration,
};

use bytes::BytesMut;
use ipnet::IpNet;
use net_route::{Handle, Route};
use tracing::warn;
use windows_sys::{
    core::PCSTR,
    Win32::{
        NetworkManagement::IpHelper::{
            if_nametoindex, GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
            GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST, IP_ADAPTER_ADDRESSES_LH,
        },
        Networking::WinSock::{
            htonl, setsockopt, WSAGetLastError, AF_UNSPEC, IPPROTO_IP, IPPROTO_IPV6,
            IPV6_UNICAST_IF, IP_UNICAST_IF, SOCKET, SOCKET_ERROR,
        },
    },
};

/// Set platform specific route configuration
pub async fn set_route_configuration(
    ifname: String,
    routes: Vec<IpNet>,
    remove: bool,
) -> io::Result<()> {
    for route in routes {
        let mut binding = Command::new("netsh");
        let mut cmd = binding
            .arg("interface")
            .arg(if route.addr().is_ipv4() {
                "ipv4"
            } else {
                "ipv6"
            })
            .arg(if remove { "delete" } else { "add" })
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

/// Binds to a specific network interface (device)
pub fn set_ip_unicast_if<S: AsRawSocket>(
    socket: &S,
    addr: &SocketAddr,
    iface: &str,
) -> io::Result<()> {
    let handle = socket.as_raw_socket() as SOCKET;

    // Get from API GetAdaptersAddresses
    let if_index = match find_adapter_interface_index(addr, iface)? {
        Some(if_index) => if_index,
        None => unsafe {
            // Windows if_nametoindex requires a C-string for interface name
            let ifname = CString::new(iface).expect("iface");

            // https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff553788(v=vs.85)
            let if_index = if_nametoindex(ifname.as_ptr() as PCSTR);
            if if_index == 0 {
                // If the if_nametoindex function fails and returns zero, it is not possible to determine an error code.
                tracing::error!("if_nametoindex {} fails", iface);
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    "invalid interface name",
                ));
            }

            if_index
        },
    };

    unsafe {
        // https://docs.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
        let ret = match addr {
            SocketAddr::V4(..) => {
                // Interface index is in network byte order for IPPROTO_IP.
                let if_index = htonl(if_index);
                setsockopt(
                    handle,
                    IPPROTO_IP as i32,
                    IP_UNICAST_IF as i32,
                    &if_index as *const _ as PCSTR,
                    mem::size_of_val(&if_index) as i32,
                )
            }
            SocketAddr::V6(..) => {
                // Interface index is in host byte order for IPPROTO_IPV6.
                setsockopt(
                    handle,
                    IPPROTO_IPV6 as i32,
                    IPV6_UNICAST_IF as i32,
                    &if_index as *const _ as PCSTR,
                    mem::size_of_val(&if_index) as i32,
                )
            }
        };

        if ret == SOCKET_ERROR {
            let err = io::Error::from_raw_os_error(WSAGetLastError());
            tracing::error!(
                "set IP_UNICAST_IF / IPV6_UNICAST_IF interface: {}, index: {}, error: {}",
                iface,
                if_index,
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
        if_index,
    );

    Ok(())
}

#[allow(non_snake_case)]
fn find_adapter_interface_index(addr: &SocketAddr, iface: &str) -> io::Result<Option<u32>> {
    // https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses

    let ip = addr.ip();

    unsafe {
        let mut ip_adapter_addresses_buffer = BytesMut::with_capacity(15 * 1024);
        ip_adapter_addresses_buffer.set_len(15 * 1024);

        let mut ip_adapter_addresses_buffer_size: u32 = ip_adapter_addresses_buffer.len() as u32;
        loop {
            let ret = GetAdaptersAddresses(
                AF_UNSPEC as u32,
                GAA_FLAG_SKIP_UNICAST
                    | GAA_FLAG_SKIP_ANYCAST
                    | GAA_FLAG_SKIP_MULTICAST
                    | GAA_FLAG_SKIP_DNS_SERVER,
                ptr::null(),
                ip_adapter_addresses_buffer.as_mut_ptr() as *mut _,
                &mut ip_adapter_addresses_buffer_size as *mut _,
            );

            match ret {
                ERROR_SUCCESS => break,
                ERROR_BUFFER_OVERFLOW => {
                    // resize buffer to ip_adapter_addresses_buffer_size
                    ip_adapter_addresses_buffer
                        .resize(ip_adapter_addresses_buffer_size as usize, 0);
                    continue;
                }
                ERROR_NO_DATA => return Ok(None),
                _ => {
                    let err = io::Error::new(
                        ErrorKind::Other,
                        format!("GetAdaptersAddresses failed with error: {}", ret),
                    );
                    return Err(err);
                }
            }
        }

        // IP_ADAPTER_ADDRESSES_LH is a linked-list
        let mut current_ip_adapter_address: *mut IP_ADAPTER_ADDRESSES_LH =
            ip_adapter_addresses_buffer.as_mut_ptr() as *mut _;
        while !current_ip_adapter_address.is_null() {
            let ip_adapter_address: &IP_ADAPTER_ADDRESSES_LH = &*current_ip_adapter_address;

            // Friendly Name
            let friendly_name_len: usize = libc::wcslen(ip_adapter_address.FriendlyName);
            let friendly_name_slice: &[u16] =
                slice::from_raw_parts(ip_adapter_address.FriendlyName, friendly_name_len);
            let friendly_name_os = OsString::from_wide(friendly_name_slice); // UTF-16 to UTF-8
            if let Some(friendly_name) = friendly_name_os.to_str() {
                if friendly_name == iface {
                    match ip {
                        IpAddr::V4(..) => {
                            return Ok(Some(ip_adapter_address.Anonymous1.Anonymous.IfIndex))
                        }
                        IpAddr::V6(..) => return Ok(Some(ip_adapter_address.Ipv6IfIndex)),
                    }
                }
            }

            // Adapter Name
            let adapter_name = CStr::from_ptr(ip_adapter_address.AdapterName as *mut _ as *const _);
            if adapter_name.to_bytes() == iface.as_bytes() {
                match ip {
                    IpAddr::V4(..) => {
                        return Ok(Some(ip_adapter_address.Anonymous1.Anonymous.IfIndex))
                    }
                    IpAddr::V6(..) => return Ok(Some(ip_adapter_address.Ipv6IfIndex)),
                }
            }

            current_ip_adapter_address = ip_adapter_address.Next;
        }
    }

    Ok(None)
}
