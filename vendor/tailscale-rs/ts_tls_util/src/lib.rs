#![doc = include_str!("../README.md")]

use std::sync::{Arc, LazyLock};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{
    TlsConnector,
    rustls::{ClientConfig, RootCertStore},
};
pub use tokio_rustls::{client::TlsStream, rustls::pki_types::ServerName};
use url::Url;

#[cfg(feature = "insecure")]
mod insecure;

#[cfg(feature = "insecure")]
pub use insecure::connect_insecure;

static ROOT_CERT_STORE: LazyLock<Arc<RootCertStore>> = LazyLock::new(|| {
    let mut store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };
    // burrow-headscale: optional additional trust anchors loaded from a
    // PEM bundle at $BURROW_EXTRA_CA_BUNDLE. Unlike the `insecure`
    // feature this doesn't skip verification — certs still have to
    // chain to a trusted root; we just add ours to the trusted set.
    // Intentionally non-fatal on any error (missing file, bad PEM,
    // unparseable cert) so production builds that never set this var
    // aren't affected.
    if let Ok(path) = std::env::var("BURROW_EXTRA_CA_BUNDLE") {
        match std::fs::read(&path) {
            Ok(bytes) => {
                let mut reader = std::io::BufReader::new(&bytes[..]);
                let mut added = 0usize;
                for cert in rustls_pemfile::certs(&mut reader).flatten() {
                    match store.add(cert) {
                        Ok(()) => added += 1,
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                %path,
                                "BURROW_EXTRA_CA_BUNDLE: skipped an unparseable cert"
                            );
                        }
                    }
                }
                tracing::info!(%path, added, "BURROW_EXTRA_CA_BUNDLE: loaded extra trust anchors");
            }
            Err(e) => {
                tracing::warn!(error = %e, %path, "BURROW_EXTRA_CA_BUNDLE: failed to read bundle");
            }
        }
    }
    Arc::new(store)
});

/// Establishes a TLS stream with a server over an existing connection.
///
/// See module-level documentation for information on root certificates.
pub async fn connect<Io>(server_name: ServerName<'_>, io: Io) -> tokio::io::Result<TlsStream<Io>>
where
    Io: AsyncRead + AsyncWrite + Unpin,
{
    connect_alpn::<Io>(server_name, io, []).await
}

/// Establishes a TLS stream with a server over an existing connection, with an optional set of
/// ALPN protocols to negotiate.
///
/// See module-level documentation for information on root certificates.
pub async fn connect_alpn<Io>(
    server_name: ServerName<'_>,
    io: Io,
    alpn: impl IntoIterator<Item = Vec<u8>>,
) -> tokio::io::Result<TlsStream<Io>>
where
    Io: AsyncRead + AsyncWrite + Unpin,
{
    // TODO(npry): custom tls cert verifier to support commonname overrides and self-signed certs
    let mut rustls_config = ClientConfig::builder()
        .with_root_certificates(ROOT_CERT_STORE.clone())
        .with_no_client_auth();

    rustls_config
        .alpn_protocols
        .extend(alpn.into_iter().map(|x| x.to_owned()));

    let connector = TlsConnector::from(Arc::new(rustls_config));

    let stream = connector.connect(server_name.to_owned(), io).await?;

    Ok(stream)
}

/// If possible, converts the host portion of the given [`Url`] to a [`ServerName`] for establishing
/// TLS streams.
pub fn server_name(url: &Url) -> Option<ServerName<'_>> {
    ServerName::try_from(url.host_str()?).ok()
}
