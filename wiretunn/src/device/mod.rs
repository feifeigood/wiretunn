mod allowed_ips;
mod config;
mod peer;

use std::{
    io::{self, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
    time::Duration,
};

use boringtun::{
    noise::{
        errors::WireGuardError, handshake::parse_handshake_anon, rate_limiter::RateLimiter, Packet,
        Tunn, TunnResult,
    },
    x25519,
};
use dashmap::DashMap;
use futures::FutureExt;

use parking_lot::RwLock;
use rand_core::{OsRng, RngCore};
use socket2::{Domain, Protocol, Type};
use tokio::{
    net::UdpSocket,
    sync::{
        mpsc::{UnboundedReceiver, UnboundedSender},
        Mutex,
    },
    task::JoinSet,
    time,
};
use tokio_util::sync::CancellationToken;
use tracing::*;

use allowed_ips::AllowedIps;
use peer::{AllowedIP, Peer};

pub use config::WgDeviceConfig;

use crate::{tun, Error};

const HANDSHAKE_RATE_LIMIT: u64 = 100; // The number of handshakes per second we can tolerate before using cookies

const MAX_UDP_SIZE: usize = (1 << 16) - 1;

#[derive(Default, Debug)]
pub struct WgDeviceBuilder {}

impl WgDeviceBuilder {
    pub async fn build(
        &self,
        tun_device: tun::Tun,
        config: WgDeviceConfig,
    ) -> Result<WgDevice, Error> {
        let name = tun_device.tun_name()?;
        let (iface_input, iface_output) = tun_device.run()?;
        let mut device_inner = WgDeviceInner {
            key_pair: RwLock::new(Default::default()),
            listen_port: Default::default(),
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            fwmark: Default::default(),
            iface: iface_input,
            udp4: Default::default(),
            udp6: Default::default(),
            use_connected_socket: config.use_connected_socket,
            peers: Default::default(),
            peers_by_ip: RwLock::new(AllowedIps::new()),
            peers_by_idx: Default::default(),
            next_index: parking_lot::Mutex::new(Default::default()),
            rate_limiter: RwLock::new(Default::default()),
        };
        device_inner.set_key(&config.private_key);
        device_inner.open_listen_socket(0).await?; // Start listening on a random port

        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        if let Some(mark) = config.fwmark {
            device_inner.set_fwmark(mark).await?;
        }

        for peer in config.wg_peers.iter() {
            let pub_key = peer.public_key;
            let preshared_key = peer.preshared_key;
            let endpoint = peer.endpoint;
            let allowed_ips = peer
                .allowed_ips
                .iter()
                .map(|x| AllowedIP::from(*x))
                .collect::<Vec<AllowedIP>>();

            device_inner
                .update_peer(
                    pub_key,
                    false,
                    false,
                    endpoint,
                    allowed_ips.as_slice(),
                    None,
                    preshared_key,
                )
                .await;
        }

        let mut device = WgDevice {
            config,
            name,
            device_inner: Arc::new(device_inner),
            join_set: JoinSet::new(),
            shutdown_token: CancellationToken::new(),
        };

        device.register_iface_handler(iface_output)?;
        device.register_udp_handler(device.device_inner.udp4.clone().expect("Not connected"))?;
        device.register_udp_handler(device.device_inner.udp6.clone().expect("Not connected"))?;
        device.register_timers()?;

        // TODO: register peer update handler

        Ok(device)
    }
}

pub struct WgDevice {
    #[allow(unused)]
    config: WgDeviceConfig,

    name: String,
    device_inner: Arc<WgDeviceInner>,

    join_set: JoinSet<Result<(), Error>>,
    shutdown_token: CancellationToken,
}

impl Drop for WgDevice {
    fn drop(&mut self) {
        self.join_set.abort_all()
    }
}

impl WgDevice {
    pub fn builder() -> WgDeviceBuilder {
        WgDeviceBuilder::default()
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub async fn wait_until_exit(&mut self) -> Result<(), Error> {
        block_until_done(&mut self.join_set).await
    }

    pub async fn shutdown_gracefully(&mut self) {
        self.shutdown_token.cancel();
    }

    pub fn register_iface_handler(
        &mut self,
        mut iface_output: UnboundedReceiver<Vec<u8>>,
    ) -> Result<(), Error> {
        // The iface_handler handles packets received from the WireGuard virtual network
        // interface. The flow is as follows:
        // * Read a packet
        // * Determine peer based on packet destination ip
        // * Encapsulate the packet for the given peer
        // * Send encapsulated packet to the peer's endpoint
        let mut dst_buf = [0u8; MAX_UDP_SIZE];
        let shutdown = self.shutdown_token.clone();
        let d = self.device_inner.clone();

        info!("WireGuard {} register interface handler", self.name);

        self.join_set.spawn(async move {
            loop {
                tokio::select! {
                    packet = iface_output.recv() => {
                        let packet = match packet {
                            Some(pkt) => pkt,
                            None =>{
                                trace!("tun device input channel closed");
                                break
                            }
                        };
                        d.handle_iface_packet(&packet, &mut dst_buf).await;
                    }
                    _ = shutdown.cancelled() => break,
                }
            }
            Ok(())
        });

        Ok(())
    }

    pub fn register_udp_handler(&mut self, udp: Arc<UdpSocket>) -> Result<(), Error> {
        let shutdown = self.shutdown_token.clone();
        let d = self.device_inner.clone();
        let mut recv_buf = [0u8; MAX_UDP_SIZE];
        let mut dst_buf = [0u8; MAX_UDP_SIZE];

        info!(
            "WireGuard {} register udp({}) handler",
            self.name,
            udp.local_addr().unwrap()
        );

        self.join_set.spawn(async move {
            let mut inner_join_set = JoinSet::new();
            loop {
                let (n, addr) = tokio::select! {
                    result = udp.recv_from(&mut recv_buf[..]) => match result {
                        Ok((n, addr)) => (n, addr),
                        Err(_) => continue,
                    },
                    _ = shutdown.cancelled() => break,
                };

                if let Ok(Some(peer)) = d
                    .handle_udp_packet(&udp, addr, &recv_buf[..n], &mut dst_buf)
                    .await
                {
                    // This packet was OK, that means we want to create a connected socket for this peer
                    let d = Arc::clone(&d);
                    let shutdown = shutdown.clone();
                    let peer_addr = addr.ip();
                    let p = peer.lock().await;
                    p.set_endpoint(addr);
                    if d.use_connected_socket {
                        if let Ok(sock) = p.connect_endpoint(
                            d.listen_port,
                            #[cfg(any(
                                target_os = "android",
                                target_os = "fuchsia",
                                target_os = "linux"
                            ))]
                            d.fwmark,
                        ) {
                            let mut recv_buf = [0u8; MAX_UDP_SIZE];
                            let mut dst_buf = [0u8; MAX_UDP_SIZE];
                            let peer = Arc::clone(&peer);
                            let udp = UdpSocket::from_std(sock.into()).unwrap();
                            inner_join_set.spawn(async move {
                                loop {
                                    let n = tokio::select! {
                                        result = udp.recv(&mut recv_buf) => match result {
                                            Ok(n) => n,
                                            Err(_) => break,
                                        },
                                        _ = shutdown.cancelled() => break,
                                    };

                                    d.handle_connect_udp_packet(
                                        &udp,
                                        &peer,
                                        peer_addr,
                                        &recv_buf[..n],
                                        &mut dst_buf,
                                    )
                                    .await;
                                }
                            });
                            reap_tasks(&mut inner_join_set);
                        }
                    }
                }
            }

            Ok(())
        });

        Ok(())
    }

    pub fn register_timers(&mut self) -> Result<(), Error> {
        let shutdown = self.shutdown_token.clone();
        let d = self.device_inner.clone();

        info!("WireGuard {} register timers", self.name);

        self.join_set.spawn(async move {
            let mut dst_buf = [0u8; MAX_UDP_SIZE];
            let mut rate_limiter_interval = time::interval(Duration::from_secs(1));
            let mut update_peer_interval = time::interval(Duration::from_secs(25));

            loop {
                tokio::select! {
                    // Reset the rate limiter every second give or take
                    _ = rate_limiter_interval.tick() => {
                        if let Some(r) = d.rate_limiter.read().as_ref() {
                            r.reset_count()
                        }
                    }
                    // Execute the timed function of every peer in the list
                    _ = update_peer_interval.tick() => {
                        // TODO: tick for every peer with different interval
                        let peer_map = &d.peers;

                        let (udp4, udp6) = match (d.udp4.as_ref(), d.udp6.as_ref()) {
                            (Some(udp4), Some(udp6)) => (udp4.clone(), udp6.clone()),
                            _ => continue,
                        };

                        // Go over each peer and invoke the timer function
                        for peer in peer_map.iter() {
                            let mut p = peer.lock().await;
                            let endpoint_addr = match p.endpoint().addr {
                                Some(addr) => addr,
                                None => continue,
                            };

                            match p.update_timers(&mut dst_buf[..]) {
                                TunnResult::Done => {},
                                TunnResult::Err(WireGuardError::ConnectionExpired) => {
                                    p.shutdown_endpoint(); // close open udp socket
                                }
                                TunnResult::Err(e) => {error!(message = "Timer error", error = ?e)},
                                TunnResult::WriteToNetwork(packet) => {
                                    match endpoint_addr {
                                        SocketAddr::V4(_) => {
                                            udp4.send_to(packet, &endpoint_addr).await.ok()
                                        }
                                        SocketAddr::V6(_) => {
                                            udp6.send_to(packet, &endpoint_addr).await.ok()
                                        }
                                    };
                                }
                                _ => panic!("Unexpected result from update_timers"),
                            };
                        }
                    }
                    _ = shutdown.cancelled() => break,
                }
            }
            Ok(())
        });

        Ok(())
    }
}

async fn block_until_done(join_set: &mut JoinSet<Result<(), Error>>) -> Result<(), Error> {
    if join_set.is_empty() {
        trace!("block_until_done called with no pending tasks");
        return Ok(());
    }

    // Now wait for all of the tasks to complete.
    let mut out = Ok(());
    while let Some(join_result) = join_set.join_next().await {
        match join_result {
            Ok(result) => {
                match result {
                    Ok(_) => (),
                    Err(e) => {
                        // Save the last error.
                        out = Err(e);
                    }
                }
            }
            Err(e) => return Err(io::Error::other(e.to_string()).into()),
        }
    }
    out
}

pub(super) struct WgDeviceInner {
    key_pair: RwLock<Option<(x25519::StaticSecret, x25519::PublicKey)>>,

    listen_port: u16,
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    fwmark: Option<u32>,

    iface: UnboundedSender<Vec<u8>>,
    udp4: Option<Arc<UdpSocket>>,
    udp6: Option<Arc<UdpSocket>>,

    use_connected_socket: bool,

    peers: DashMap<x25519::PublicKey, Arc<Mutex<Peer>>>,
    peers_by_ip: RwLock<AllowedIps<Arc<Mutex<Peer>>>>,
    peers_by_idx: DashMap<u32, Arc<Mutex<Peer>>>,
    next_index: parking_lot::Mutex<IndexLfsr>,

    rate_limiter: RwLock<Option<Arc<RateLimiter>>>,
}

impl WgDeviceInner {
    async fn next_index(&self) -> u32 {
        self.next_index.lock().next()
    }

    pub async fn open_listen_socket(&mut self, mut port: u16) -> Result<(), Error> {
        // Binds the network facing interfaces
        // First close any existing open socket, and remove them from the event loop
        // TODO: how to confirm udp socket has been close?
        if let Some(_s) = self.udp4.take() {}
        if let Some(_s) = self.udp6.take() {}

        for peer in self.peers.iter_mut() {
            peer.lock().await.shutdown_endpoint();
        }

        // Then open new sockets and bind to the port
        let udp_sock4 = socket2::Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        udp_sock4.set_reuse_address(true)?;
        udp_sock4.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into())?;
        udp_sock4.set_nonblocking(true)?;

        if port == 0 {
            // Random port was assigned
            port = udp_sock4.local_addr()?.as_socket().unwrap().port();
        }

        let udp_sock6 = socket2::Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        udp_sock6.set_reuse_address(true)?;
        udp_sock6.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).into())?;
        udp_sock6.set_nonblocking(true)?;

        self.udp4 = Some(Arc::new(UdpSocket::from_std(udp_sock4.into())?));
        self.udp6 = Some(Arc::new(UdpSocket::from_std(udp_sock6.into())?));

        self.listen_port = port;

        Ok(())
    }

    pub async fn handle_connect_udp_packet(
        &self,
        udp: &UdpSocket,
        peer: &Arc<Mutex<Peer>>,
        peer_addr: IpAddr,
        packet: &[u8],
        dst_buf: &mut [u8],
    ) {
        let mut flush = false;
        let mut p = peer.lock().await;
        match p
            .tunnel
            .decapsulate(Some(peer_addr), packet, &mut dst_buf[..])
        {
            TunnResult::Done => {}
            TunnResult::Err(e) => error!("Decapsulate error {:?}", e),
            TunnResult::WriteToNetwork(packet) => {
                flush = true;
                let _: Result<_, _> = udp.try_send(packet);
            }
            TunnResult::WriteToTunnelV4(packet, addr) => {
                if p.is_allowed_ip(addr) {
                    _ = self.iface.send(packet.to_vec());
                }
            }
            TunnResult::WriteToTunnelV6(packet, addr) => {
                if p.is_allowed_ip(addr) {
                    _ = self.iface.send(packet.to_vec());
                }
            }
        };

        if flush {
            // Flush pending queue
            while let TunnResult::WriteToNetwork(packet) =
                p.tunnel.decapsulate(None, &[], &mut dst_buf[..])
            {
                let _: Result<_, _> = udp.try_send(packet);
            }
        }
    }

    pub async fn handle_udp_packet(
        &self,
        udp: &UdpSocket,
        addr: SocketAddr,
        packet: &[u8],
        dst_buf: &mut [u8],
    ) -> Result<Option<Arc<Mutex<Peer>>>, Error> {
        // The rate limiter initially checks mac1 and mac2, and optionally asks to send a cookie
        let parsed_packet = match self.rate_limiter.read().as_ref().unwrap().verify_packet(
            Some(addr.ip()),
            packet,
            dst_buf,
        ) {
            Ok(packet) => packet,
            Err(TunnResult::WriteToNetwork(cookie)) => {
                let _: Result<_, _> = udp.try_send_to(cookie, addr);
                return Ok(None);
            }
            Err(_) => return Ok(None),
        };

        let peer = match &parsed_packet {
            Packet::HandshakeInit(p) => {
                let key_pair = &self.key_pair.read();
                let (private_key, public_key) = key_pair.as_ref().expect("Key is not set");
                parse_handshake_anon(private_key, public_key, p)
                    .ok()
                    .and_then(|hh| self.find_peer(&x25519::PublicKey::from(hh.peer_static_public)))
            }
            Packet::HandshakeResponse(p) => self.find_peer_by_idx(&(p.receiver_idx >> 8)),
            Packet::PacketCookieReply(p) => self.find_peer_by_idx(&(p.receiver_idx >> 8)),
            Packet::PacketData(p) => self.find_peer_by_idx(&(p.receiver_idx >> 8)),
        };

        let peer = match peer {
            None => return Ok(None),
            Some(peer) => peer,
        };

        let mut p = peer.lock().await;

        // We found a peer, use it to decapsulate the message+
        let mut flush = false; // Are there packets to send from the queue?
        match p
            .tunnel
            .handle_verified_packet(parsed_packet, &mut dst_buf[..])
        {
            TunnResult::Done => {}
            TunnResult::Err(_) => return Ok(None),
            TunnResult::WriteToNetwork(packet) => {
                flush = true;
                let _: Result<_, _> = udp.try_send_to(packet, addr);
            }
            TunnResult::WriteToTunnelV4(packet, addr) => {
                if p.is_allowed_ip(addr) {
                    // TODO: avoid copy packet
                    _ = self.iface.send(packet.to_vec());
                }
            }
            TunnResult::WriteToTunnelV6(packet, addr) => {
                if p.is_allowed_ip(addr) {
                    _ = self.iface.send(packet.to_vec());
                }
            }
        };

        if flush {
            // Flush pending queue
            while let TunnResult::WriteToNetwork(packet) =
                p.tunnel.decapsulate(None, &[], &mut dst_buf[..])
            {
                let _: Result<_, _> = udp.try_send_to(packet, addr);
            }
        }

        Ok(Some(Arc::clone(&peer)))
    }

    pub async fn handle_iface_packet(&self, packet: &[u8], dst_buf: &mut [u8]) {
        trace_ip_packet("Received IP packet", packet);

        let dst_addr = match Tunn::dst_address(packet) {
            Some(addr) => addr,
            None => return,
        };

        let peer = match self.find_peer_by_ip(dst_addr) {
            Some(peer) => peer,
            None => return,
        };
        let mut peer = peer.lock().await;

        match peer.tunnel.encapsulate(packet, dst_buf) {
            TunnResult::Done => {}
            TunnResult::Err(e) => {
                error!(message = "Encapsulate error", error = ?e)
            }
            TunnResult::WriteToNetwork(packet) => {
                let mut endpoint = peer.endpoint_mut();
                if let Some(conn) = endpoint.conn.as_mut() {
                    // Prefer to send using the connected socket
                    let _: Result<_, _> = conn.write(&packet);
                } else if let Some(addr @ SocketAddr::V4(_)) = endpoint.addr {
                    let _: Result<_, _> = self.udp4.as_ref().unwrap().try_send_to(packet, addr);
                } else if let Some(addr @ SocketAddr::V6(_)) = endpoint.addr {
                    let _: Result<_, _> = self.udp6.as_ref().unwrap().try_send_to(packet, addr);
                } else {
                    error!("No endpoint");
                }
            }
            _ => panic!("Unexpected result from encapsulate"),
        };
    }

    pub fn set_key(&self, private_key: &x25519::StaticSecret) {
        let public_key = x25519::PublicKey::from(private_key);
        let key_pair = Some((private_key.clone(), public_key));

        // x25519 (rightly) doesn't let us expose secret keys for comparison.
        // If the public keys are the same, then the private keys are the same.
        if Some(&public_key) == self.key_pair.read().as_ref().map(|p| &p.1) {
            return;
        }

        let rate_limiter = Arc::new(RateLimiter::new(&public_key, HANDSHAKE_RATE_LIMIT));

        *self.key_pair.write() = key_pair;
        *self.rate_limiter.write() = Some(rate_limiter);
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    pub async fn set_fwmark(&mut self, mark: u32) -> Result<(), Error> {
        self.fwmark = Some(mark);

        // First set fwmark on listeners
        if let Some(ref sock) = self.udp4 {
            set_socket_fwmark(sock, mark)?;
        }

        if let Some(ref sock) = self.udp6 {
            set_socket_fwmark(sock, mark)?;
        }

        // Then on all currently connected sockets
        for peer in self.peers.iter() {
            if let Some(ref sock) = peer.lock().await.endpoint().conn {
                set_socket_fwmark(sock, mark)?;
            }
        }

        Ok(())
    }

    pub async fn remove_peer(&self, pub_key: &x25519::PublicKey) {
        if let Some((_, peer)) = self.peers.remove(pub_key) {
            // Found a peer to remove, now purge all references to it:
            {
                let p = peer.lock().await;
                p.shutdown_endpoint(); // close open udp socket and free the closure
                self.peers_by_idx.remove(&p.index());
            }
            self.peers_by_ip
                .write()
                .remove(&|p: &Arc<Mutex<Peer>>| Arc::ptr_eq(&peer, p));

            info!("Peer removed");
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_peer(
        &self,
        pub_key: x25519::PublicKey,
        remove: bool,
        _replace_ips: bool,
        endpoint: Option<SocketAddr>,
        allowed_ips: &[AllowedIP],
        keepalive: Option<u16>,
        preshared_key: Option<[u8; 32]>,
    ) {
        if remove {
            // Completely remove a peer
            return self.remove_peer(&pub_key).await;
        }

        // Update an existing peer
        if self.peers.get(&pub_key).is_some() {
            // We already have a peer, we need to merge the existing config into the newly created one
            panic!("Modifying existing peers is not yet supported. Remove and add again instead.");
        }

        let next_index = self.next_index().await;
        let device_key_pair = self
            .key_pair
            .read()
            .clone()
            .expect("Private key must be set first");

        let tunn = Tunn::new(
            device_key_pair.0.clone(),
            pub_key,
            preshared_key,
            keepalive,
            next_index,
            None,
        );

        let peer = Peer::new(tunn, next_index, endpoint, allowed_ips, preshared_key);

        let peer = Arc::new(Mutex::new(peer));
        self.peers.insert(pub_key, Arc::clone(&peer));
        self.peers_by_idx.insert(next_index, Arc::clone(&peer));
        {
            let mut peers_by_ip = self.peers_by_ip.write();
            for AllowedIP { addr, cidr } in allowed_ips {
                peers_by_ip.insert(*addr, *cidr as _, Arc::clone(&peer));
            }
        }

        info!("Peer added");
    }

    pub fn clear_peers(&self) {
        self.peers.clear();
        self.peers_by_idx.clear();
        self.peers_by_ip.write().clear();
    }

    pub fn find_peer(&self, pub_key: &x25519::PublicKey) -> Option<Arc<Mutex<Peer>>> {
        self.peers.get(pub_key).map(|x| x.value().clone())
    }

    pub fn find_peer_by_ip(&self, addr: IpAddr) -> Option<Arc<Mutex<Peer>>> {
        self.peers_by_ip.read().find(addr).cloned()
    }

    pub fn find_peer_by_idx(&self, idx: &u32) -> Option<Arc<Mutex<Peer>>> {
        self.peers_by_idx.get(idx).map(|x| x.value().clone())
    }
}

/// A basic linear-feedback shift register implemented as xorshift, used to
/// distribute peer indexes across the 24-bit address space reserved for peer
/// identification.
/// The purpose is to obscure the total number of peers using the system and to
/// ensure it requires a non-trivial amount of processing power and/or samples
/// to guess other peers' indices. Anything more ambitious than this is wasted
/// with only 24 bits of space.
pub(crate) struct IndexLfsr {
    initial: u32,
    lfsr: u32,
    mask: u32,
}

impl IndexLfsr {
    /// Generate a random 24-bit nonzero integer
    fn random_index() -> u32 {
        const LFSR_MAX: u32 = 0xffffff; // 24-bit seed
        loop {
            let i = OsRng.next_u32() & LFSR_MAX;
            if i > 0 {
                // LFSR seed must be non-zero
                return i;
            }
        }
    }

    /// Generate the next value in the pseudorandom sequence
    fn next(&mut self) -> u32 {
        // 24-bit polynomial for randomness. This is arbitrarily chosen to
        // inject bitflips into the value.
        const LFSR_POLY: u32 = 0xd80000; // 24-bit polynomial
        let value = self.lfsr - 1; // lfsr will never have value of 0
        self.lfsr = (self.lfsr >> 1) ^ ((0u32.wrapping_sub(self.lfsr & 1u32)) & LFSR_POLY);
        assert!(self.lfsr != self.initial, "Too many peers created");
        value ^ self.mask
    }
}

impl Default for IndexLfsr {
    fn default() -> Self {
        let seed = Self::random_index();
        IndexLfsr {
            initial: seed,
            lfsr: seed,
            mask: Self::random_index(),
        }
    }
}

/// Sets the value for the `SO_MARK` option on this socket.
#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
fn set_socket_fwmark<S>(socket: &S, mark: u32) -> io::Result<()>
where
    S: std::os::unix::io::AsRawFd,
{
    use socket2::Socket;
    use std::os::unix::prelude::{FromRawFd, IntoRawFd};

    let fd = socket.as_raw_fd();

    let sock = unsafe { Socket::from_raw_fd(fd) };
    let result = sock.set_mark(mark);

    sock.into_raw_fd();

    result
}

/// Reap finished tasks from a `JoinSet`, without awaiting or blocking.
fn reap_tasks(join_set: &mut JoinSet<()>) {
    while FutureExt::now_or_never(join_set.join_next())
        .flatten()
        .is_some()
    {}
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
