/// General categories of error that can occur during any phase of an HTTP connection.
#[derive(Debug, Copy, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// A function argument or field value wasn't populated, or contained an invalid value.
    #[error("invalid parameter")]
    InvalidParam,

    /// An underlying I/O error occurred that prevented a connection from being established, a
    /// request from being sent, or a response from being read.
    #[error("i/o error encountered")]
    Io,

    /// A timeout expired while waiting for the server to respond, or the client (us) didn't send
    /// request headers within the timeframe the server expected.
    #[error("timed out")]
    Timeout,
}

impl From<hyper::Error> for Error {
    fn from(e: hyper::Error) -> Self {
        if e.is_timeout() {
            Error::Timeout
        } else if e.is_parse() || e.is_parse_status() {
            Error::InvalidParam
        } else {
            Error::Io
        }
    }
}
