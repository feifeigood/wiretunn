#[cfg(unix)]
use std::os::unix::io::RawFd;

use ipnet::IpNet;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
};
use tracing::{error, trace};
use tun2::{AbstractDevice, AsyncDevice, Configuration as TunConfiguration, Layer};

use crate::Error;

pub use self::sys::set_route_configuration;

mod sys;

#[derive(Default)]
pub struct TunBuilder {
    tun_config: TunConfiguration,
}

impl TunBuilder {
    pub fn tun_name(&mut self, name: &str) {
        self.tun_config.tun_name(name);
    }

    pub fn address(&mut self, addr: IpNet) {
        self.tun_config.address(addr.addr()).netmask(addr.netmask());
    }

    pub fn destination(&mut self, addr: IpNet) {
        self.tun_config.destination(addr.addr());
    }

    #[cfg(unix)]
    pub fn file_descriptor(&mut self, fd: RawFd) {
        self.tun_config.raw_fd(fd);
    }

    pub fn mtu(&mut self, mtu: u16) {
        self.tun_config.mtu(mtu);
    }

    // Build Tun Device
    pub async fn build(mut self) -> Result<Tun, Error> {
        self.tun_config.layer(Layer::L3).up();

        #[cfg(target_os = "linux")]
        self.tun_config.platform_config(|config| {
            config.ensure_root_privileges(true);
        });

        #[cfg(target_os = "windows")]
        config.platform_config(|config| {
            config.device_guid(deterministic_guid(config.name()));
        });

        let device = tun2::create_as_async(&self.tun_config)?;

        Ok(Tun { device })
    }
}

pub struct Tun {
    device: AsyncDevice,
}

impl Tun {
    pub fn tun_name(&self) -> Result<String, Error> {
        self.device.as_ref().tun_name().map_err(Error::TunError)
    }

    #[allow(clippy::type_complexity)]
    pub fn run(
        mut self,
    ) -> Result<
        (
            mpsc::UnboundedSender<Vec<u8>>,
            mpsc::UnboundedReceiver<Vec<u8>>,
        ),
        Error,
    > {
        let mut recv_buf = vec![0u8; 65536];
        let (iface_tx, iface_output) = mpsc::unbounded_channel::<Vec<u8>>();
        let (iface_input, mut iface_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    // tun device read
                    n = self.device.read(&mut recv_buf) => {
                        let n = n?;
                        if let Err(e) = iface_tx.send(recv_buf[..n].to_vec()) {
                            error!("failed to sent IP packet to tun device output channel, error: {:?}", e);
                        }
                    }
                    // tun device write
                    packet = iface_rx.recv() => {
                        let packet = match packet {
                            Some(pkt) => pkt,
                            None => {
                                trace!("tun device input channel closed");
                                break
                            }
                        };
                        if let Err(e) = self.device.write(&packet).await {
                            error!("failed to sent IP packet, error: {:?}", e);
                        }
                    }
                }
            }
            Ok::<(), Error>(())
        });

        Ok((iface_input, iface_output))
    }
}

#[cfg(windows)]
fn deterministic_guid(ifname: &str) -> Option<u128> {
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