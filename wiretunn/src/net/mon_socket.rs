//! UDP socket with flow statistic monitored

use std::{io, net::SocketAddr, sync::Arc};

use tokio::net::{ToSocketAddrs, UdpSocket};

use super::stats::FlowStat;

/// Monitored `UdpSocket`
pub struct MonSocket {
    socket: UdpSocket,
    flow_stat: Arc<FlowStat>,
}

impl MonSocket {
    /// Create a new socket with flow monitor
    pub fn from_socket(socket: UdpSocket, flow_stat: Arc<FlowStat>) -> MonSocket {
        MonSocket { socket, flow_stat }
    }

    /// Sends data on the socket to the remote address that the socket is
    /// connected to.
    ///
    #[inline]
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        let n = self.socket.send(buf).await?;
        self.flow_stat.incr_tx(n as u64);
        Ok(n)
    }

    /// Sends data on the socket to the given address. On success, returns the
    /// number of bytes written.
    ///
    #[inline]
    pub async fn send_to<A: ToSocketAddrs>(&self, buf: &[u8], target: A) -> io::Result<usize> {
        let n = self.socket.send_to(buf, target).await?;
        self.flow_stat.incr_tx(n as u64);
        Ok(n)
    }

    #[inline]
    pub fn try_send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        let n = self.socket.try_send_to(buf, target)?;
        self.flow_stat.incr_tx(n as u64);
        Ok(n)
    }

    /// Receives a single datagram message on the socket from the remote address
    /// to which it is connected. On success, returns the number of bytes read.
    ///
    #[inline]
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.socket.recv(buf).await?;
        self.flow_stat.incr_rx(n as u64);
        Ok(n)
    }

    /// Receives a single datagram message on the socket. On success, returns
    /// the number of bytes read and the origin.
    ///
    #[inline]
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (n, addr) = self.socket.recv_from(buf).await?;
        self.flow_stat.incr_rx(n as u64);
        Ok((n, addr))
    }

    #[inline]
    pub fn get_ref(&self) -> &UdpSocket {
        &self.socket
    }

    #[inline]
    pub fn flow_stat(&self) -> &FlowStat {
        &self.flow_stat
    }
}
