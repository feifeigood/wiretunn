use std::net::SocketAddr;

use boringtun::x25519;
use ipnet::IpNet;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct WgDeviceConfig {
    #[serde(deserialize_with = "deserialize::wg_private_key")]
    pub private_key: x25519::StaticSecret,
    pub listen_port: Option<u16>,
    pub address: IpNet,
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    pub fwmark: Option<u32>,
    pub mtu: Option<i32>,
    #[serde(default)]
    pub use_connected_socket: bool,
    #[serde(rename = "peer")]
    pub wg_peers: Vec<WgPeerConfig>,
}

#[derive(Deserialize)]
pub struct WgPeerConfig {
    #[serde(deserialize_with = "deserialize::wg_public_key")]
    pub public_key: x25519::PublicKey,
    #[serde(default, deserialize_with = "deserialize::wg_preshared_key")]
    pub preshared_key: Option<[u8; 32]>,
    #[serde(deserialize_with = "deserialize::wg_allowed_ips")]
    pub allowed_ips: Vec<IpNet>,
    pub persistent_keepalive: Option<u16>,
    #[serde(deserialize_with = "deserialize::wg_endpoint")]
    pub endpoint: Option<SocketAddr>,
}

mod deserialize {

    use std::net::{SocketAddr, ToSocketAddrs};

    use base64::prelude::*;
    use boringtun::x25519;
    use ipnet::IpNet;
    use serde::{Deserialize, Deserializer};

    pub fn wg_private_key<'de, D>(deserializer: D) -> Result<x25519::StaticSecret, D::Error>
    where
        D: Deserializer<'de>,
    {
        let key = String::deserialize(deserializer)?;
        let bytes: [u8; 32] = BASE64_STANDARD
            .decode(&key)
            .map_err(|_| {
                serde::de::Error::custom(format!(
                    "Key is not the correct length or format: {}",
                    key
                ))
            })?
            .try_into()
            .unwrap();

        Ok(x25519::StaticSecret::from(bytes))
    }

    pub fn wg_public_key<'de, D>(deserializer: D) -> Result<x25519::PublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let key = String::deserialize(deserializer)?;
        let bytes: [u8; 32] = BASE64_STANDARD
            .decode(&key)
            .map_err(|_| {
                serde::de::Error::custom(format!(
                    "Key is not the correct length or format: {}",
                    key
                ))
            })?
            .try_into()
            .unwrap();

        Ok(x25519::PublicKey::from(bytes))
    }

    pub fn wg_preshared_key<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let key = String::deserialize(deserializer)?;
        let bytes: [u8; 32] = BASE64_STANDARD
            .decode(&key)
            .map_err(|_| {
                serde::de::Error::custom(format!(
                    "Key is not the correct length or format: {}",
                    key
                ))
            })?
            .try_into()
            .unwrap();

        Ok(Some(bytes))
    }

    pub fn wg_allowed_ips<'de, D>(deserializer: D) -> Result<Vec<IpNet>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut allowed_ips = Vec::new();
        for allowed_ip in String::deserialize(deserializer)?
            .split(',')
            .map(str::trim)
            .collect::<Vec<&str>>()
        {
            allowed_ips.push(allowed_ip.parse::<IpNet>().map_err(|_| {
                serde::de::Error::custom(format!("Unable to parse IP address: {}", allowed_ip))
            })?);
        }

        Ok(allowed_ips)
    }

    pub fn wg_endpoint<'de, D>(deserializer: D) -> Result<Option<SocketAddr>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let endpoint = String::deserialize(deserializer)?;
        match endpoint.parse::<SocketAddr>() {
            Ok(saddr) => Ok(Some(saddr)),
            Err(_) => {
                // maybe endpoint is domain, try resolve it
                Ok(endpoint
                    .to_socket_addrs()
                    .map_err(|_| {
                        serde::de::Error::custom(format!("Unable to parse Endpoint: {}", endpoint))
                    })?
                    .next())
            }
        }
    }
}
