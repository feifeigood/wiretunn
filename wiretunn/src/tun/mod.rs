#[cfg(unix)]
use std::os::unix::io::RawFd;

use ipnet::IpNet;
use std::net::IpAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
};
use tracing::{error, trace, Level};
use tun2::{AbstractDevice, AsyncDevice, Configuration as TunConfiguration, Layer};

use crate::Error;

#[derive(Default)]
pub struct TunBuilder {
    tun_config: TunConfiguration,
}

impl TunBuilder {
    pub fn tun_name(&mut self, name: &str) {
        self.tun_config.tun_name(name);

        #[cfg(target_os = "windows")]
        self.tun_config.platform_config(|config| {
            config.device_guid(crate::sys::deterministic_guid(name));
        });
    }

    pub fn address(&mut self, addr: IpNet) {
        self.tun_config.address(addr.addr()).netmask(addr.netmask());
    }

    pub fn destination(&mut self, addr: IpNet) {
        self.tun_config.destination(addr.addr());
    }

    #[allow(unused)]
    pub fn dns_servers(&mut self, dns_servers: Vec<IpAddr>) {
        #[cfg(target_os = "windows")]
        self.tun_config.platform_config(|config| {
            config.dns_servers(Some(dns_servers));
        });
    }

    #[cfg(unix)]
    pub fn file_descriptor(&mut self, fd: RawFd) {
        self.tun_config.raw_fd(fd);
    }

    #[cfg(unix)]
    pub fn file_descriptor_close_on_drop(&mut self, close_fd_on_drop: bool) {
        self.tun_config.close_fd_on_drop(close_fd_on_drop);
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

        let device = tun2::create_as_async(&self.tun_config)?;

        Ok(Tun { device })
    }
}

pub struct Tun {
    device: AsyncDevice,
}

impl Tun {
    pub fn tun_name(&self) -> Result<String, Error> {
        Ok(self
            .device
            .as_ref()
            .tun_name()
            .unwrap_or("<no ifname>".into()))
    }

    pub fn address(&self) -> Result<IpAddr, Error> {
        self.device.as_ref().address().map_err(Error::TunError)
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
                        let pkt = recv_buf[..n].to_vec();

                        trace_ip_packet("Recv packet", &pkt);

                        if let Err(e) = iface_tx.send(pkt) {
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

                        trace_ip_packet("Send packet", &packet);

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

fn trace_ip_packet(message: &str, packet: &[u8]) {
    if tracing::enabled!(Level::TRACE) {
        use smoltcp::wire::*;

        match IpVersion::of_packet(packet) {
            Ok(IpVersion::Ipv4) => trace!(
                "{}: {}",
                message,
                PrettyPrinter::<Ipv4Packet<&mut [u8]>>::new("", &packet)
            ),
            Ok(IpVersion::Ipv6) => trace!(
                "{}: {}",
                message,
                PrettyPrinter::<Ipv6Packet<&mut [u8]>>::new("", &packet)
            ),
            _ => {}
        }
    }
}
