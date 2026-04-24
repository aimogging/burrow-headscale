use alloc::{collections::VecDeque, vec};
use core::net::SocketAddr;

use smoltcp::{iface::SocketHandle, socket::tcp};

use crate::{
    Netstack,
    command::{
        Error, Response,
        tcp::listen::{Command as TcpListenCommand, Response as TcpListenResponse},
    },
};

/// Opaque handle to a TCP listener.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ListenerHandle(usize);

/// State for a particular TCP listener, supporting the abstraction of a single persistent
/// listener object that can spin off connections by calling `accept`.
///
/// `smoltcp` doesn't provide a TCP listener abstraction, just plain sockets. Each one has
/// its own state machine, which can be in the `LISTENING` state, i.e. waiting for a
/// connection. But once it's `ESTABLISHED`, you need to create a new `LISTENING` socket in
/// order to accept a new connection.
pub struct TcpListenerState {
    /// The local endpoint on which this listener is listening.
    local_endpoint: SocketAddr,

    /// Socket currently in listening state and waiting for a new connection.
    current_socket_handle: SocketHandle,

    /// Sockets which have upgraded from the listening state and are waiting to be accepted.
    accept_queue: VecDeque<SocketHandle>,
}

impl Netstack {
    /// Process a TCP listener command.
    #[tracing::instrument(skip_all, fields(?cmd), level = "debug")]
    pub(crate) fn process_tcp_listen(
        &mut self,
        cmd: TcpListenCommand,
        handle: Option<SocketHandle>,
    ) -> Response {
        debug_assert!(handle.is_none());

        match cmd {
            TcpListenCommand::Listen { local_endpoint } => {
                let mut listener = tcp::Socket::new(self.tcp_buffer(), self.tcp_buffer());

                if let Err(e) = listener.listen(local_endpoint) {
                    return Response::Error(e.into());
                }

                let socket_handle = self.socket_set.add(listener);

                let listener_handle = ListenerHandle(self.next_tcp_listener_id);
                self.next_tcp_listener_id += 1;

                self.tcp_listeners.insert(
                    listener_handle,
                    TcpListenerState {
                        current_socket_handle: socket_handle,
                        local_endpoint,
                        accept_queue: Default::default(),
                    },
                );

                TcpListenResponse::Listening {
                    handle: listener_handle,
                }
                .into()
            }
            TcpListenCommand::Accept { handle } => {
                let Some(listener) = self.tcp_listeners.get_mut(&handle) else {
                    tracing::error!(?handle, "listener does not exist");
                    return Error::BadRequest.into();
                };

                if let Some(handle) = listener.accept_queue.pop_front() {
                    let sock = self.socket_set.get::<tcp::Socket>(handle);
                    let remote = sock.remote_endpoint().unwrap();

                    return TcpListenResponse::Accepted {
                        handle,
                        remote: SocketAddr::new(remote.addr.into(), remote.port),
                    }
                    .into();
                }

                tracing::trace!("accept not ready");

                Response::WouldBlock {
                    handle: None,
                    command: TcpListenCommand::Accept { handle }.into(),
                }
            }
            TcpListenCommand::Close { handle } => {
                let Some(listener) = self.tcp_listeners.remove(&handle) else {
                    tracing::error!(?handle, "listener does not exist");
                    return Error::BadRequest.into();
                };

                let sock = self
                    .socket_set
                    .get_mut::<tcp::Socket>(listener.current_socket_handle);

                sock.close();

                self.pending_tcp_closes.push(listener.current_socket_handle);

                for pending_accept in listener.accept_queue {
                    let sock = self.socket_set.get_mut::<tcp::Socket>(pending_accept);
                    sock.close();

                    self.pending_tcp_closes.push(pending_accept);
                }

                Response::Ok
            }
        }
    }

    /// Attempt to accept a TCP connection for all TCP listeners.
    #[tracing::instrument(skip_all)]
    pub(crate) fn pump_tcp_accept(&mut self) {
        for listener in self.tcp_listeners.values_mut() {
            let sock = self
                .socket_set
                .get_mut::<tcp::Socket>(listener.current_socket_handle);

            let state = sock.state();
            let _span = tracing::trace_span!(
                "pump_one_tcp_listener",
                current_socket = ?listener.current_socket_handle,
                current_socket_state = %state,
                accept_queue_len = listener.accept_queue.len(),
                listening_on = %listener.local_endpoint,
            )
            .entered();

            match sock.state() {
                tcp::State::Listen => {
                    return;
                }

                tcp::State::SynReceived | tcp::State::SynSent => {
                    tracing::trace!("socket pending, not yet established");
                    return;
                }

                tcp::State::Established => {
                    tracing::trace!("connection established");

                    listener
                        .accept_queue
                        .push_back(listener.current_socket_handle);
                }

                _ => {
                    tracing::warn!("partially-established listening socket reset or closed");
                    sock.close();
                    self.pending_tcp_closes.push(listener.current_socket_handle);
                }
            }

            // fallthrough: socket has either closed or been established -- create a new listen
            // socket

            let mut new_listener = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; self.config.tcp_buffer_size]),
                tcp::SocketBuffer::new(vec![0; self.config.tcp_buffer_size]),
            );

            if let Err(e) = new_listener.listen(listener.local_endpoint) {
                // invariant failure: the only variants for ListenError are
                // InvalidState and Unaddressable. InvalidState isn't possible here because we just
                // created the socket. Unaddressable only occurs if listener.local_endpoint has
                // an unspecified (zero) port and/or address. but we're currently replacing a socket
                // with the _same_ local_endpoint, and it clearly wasn't invalid before, so
                // Unaddressable shouldn't be possible either. this should always succeed.
                panic!("opening new listen socket for accept: {e}");
            }

            let socket_handle = self.socket_set.add(new_listener);
            listener.current_socket_handle = socket_handle;
            tracing::trace!(new_handle = ?socket_handle, "replaced active listen socket");
        }
    }
}
