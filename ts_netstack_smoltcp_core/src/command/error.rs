use smoltcp::socket::{
    icmp::BindError as IcmpBindError,
    raw::BindError as RawBindError,
    tcp::{ConnectError, ListenError, SendError as TcpSendError},
    udp::{BindError as UdpBindError, SendError as UdpSendError},
};

use crate::{command, tcp};

/// Error while interacting with the netstack.
#[derive(thiserror::Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum Error {
    /// The remote end of a command or reply channel has closed. This command can't
    /// complete.
    ///
    /// Typically, this occurs if the netstack we're talking to has been dropped.
    #[error("the remote end of the channel has closed")]
    ChannelClosed,

    /// The request contained invalid parameters. Retrying will not resolve this issue.
    ///
    /// Common causes for this error are that a specified address was invalid, the socket
    /// a handle refers to no longer exists, or the packet to be sent was too large for the
    /// socket's buffer capacity.
    #[error("invalid request")]
    BadRequest,

    /// An error occurred related to TCP stream operations.
    #[error(transparent)]
    TcpStream(#[from] tcp::stream::Error),

    /// An internal invariant was violated.
    ///
    /// This indicates a bug and is likely an unrecoverable failure.
    #[error("invariant violation: unrecoverable")]
    InvariantViolated,

    /// Response was the wrong type for the given operation.
    #[error("response was the wrong type")]
    WrongType,
}

impl From<Error> for command::Response {
    fn from(value: Error) -> Self {
        command::Response::Error(value)
    }
}

impl<T> From<flume::SendError<T>> for Error {
    fn from(_: flume::SendError<T>) -> Self {
        Error::ChannelClosed
    }
}

impl From<flume::RecvError> for Error {
    fn from(_: flume::RecvError) -> Self {
        Error::ChannelClosed
    }
}

impl From<ListenError> for Error {
    fn from(value: ListenError) -> Self {
        match value {
            ListenError::InvalidState => Error::InvariantViolated,
            ListenError::Unaddressable => Error::BadRequest,
        }
    }
}

impl From<ConnectError> for Error {
    fn from(value: ConnectError) -> Self {
        match value {
            ConnectError::InvalidState => Error::InvariantViolated,
            ConnectError::Unaddressable => Error::BadRequest,
        }
    }
}

impl From<UdpBindError> for Error {
    fn from(value: UdpBindError) -> Self {
        match value {
            UdpBindError::InvalidState => Error::InvariantViolated,
            UdpBindError::Unaddressable => Error::BadRequest,
        }
    }
}

impl From<RawBindError> for Error {
    fn from(value: RawBindError) -> Self {
        match value {
            RawBindError::InvalidState => Error::InvariantViolated,
            RawBindError::Unaddressable => Error::BadRequest,
        }
    }
}

impl From<IcmpBindError> for Error {
    fn from(value: IcmpBindError) -> Self {
        match value {
            IcmpBindError::InvalidState => Error::InvariantViolated,
            IcmpBindError::Unaddressable => Error::BadRequest,
        }
    }
}

impl From<TcpSendError> for Error {
    fn from(value: TcpSendError) -> Self {
        match value {
            TcpSendError::InvalidState => tcp::stream::Error::Reset.into(),
        }
    }
}

impl From<UdpSendError> for Error {
    fn from(value: UdpSendError) -> Self {
        match value {
            UdpSendError::Unaddressable => Error::BadRequest,
            UdpSendError::BufferFull => Error::BadRequest,
        }
    }
}

#[cfg(feature = "std")]
impl From<Error> for std::io::Error {
    fn from(value: Error) -> Self {
        use std::io::{Error as StdErr, ErrorKind};

        match value {
            Error::BadRequest => StdErr::new(ErrorKind::InvalidInput, Error::BadRequest),
            Error::TcpStream(s) => s.into(),
            other => StdErr::other(other),
        }
    }
}
