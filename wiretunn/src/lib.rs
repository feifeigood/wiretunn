use std::io;

pub mod device;
pub mod rt;
pub mod signal;
pub mod tun;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    IoError(#[from] io::Error),
    #[error("{0}")]
    Connect(String),
    #[error("tun error: {0}")]
    TunError(#[from] tun2::Error),
}
