use std::{net::SocketAddr, path::PathBuf};

use clap::Parser;
use futures::future;
use h3_shim::quic::rustls;
use rustls::pki_types::CertificateDer;
use tokio::io::AsyncWriteExt;
use tracing::{error, info};

static ALPN: &[u8] = b"h3";

#[derive(Parser, Debug)]
#[structopt(name = "server")]
struct Opt {
    #[structopt(
        long,
        short,
        default_value = "examples/ca.cert",
        help = "Certificate of CA who issues the server certificate"
    )]
    pub ca: PathBuf,

    #[structopt(name = "keylog", long)]
    pub key_log_file: bool,

    #[structopt(long, short = 'b', default_value = "[::]:0")]
    pub binds: Vec<SocketAddr>,

    #[structopt(default_value = "https://localhost:4433/Cargo.toml")]
    pub uri: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .enable_io()
        .build()?;

    rt.block_on(run())
}

async fn run() -> Result<(), Box<dyn core::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_writer(std::io::stdout)
        .init();
    // console_subscriber::init();
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let opt = Opt::parse();

    // DNS lookup

    let uri = opt.uri.parse::<http::Uri>()?;

    if uri.scheme() != Some(&http::uri::Scheme::HTTPS) {
        Err("uri scheme must be 'https'")?;
    }

    let auth = uri.authority().ok_or("uri must have a host")?.clone();

    let port = auth.port_u16().unwrap_or(443);

    let addr = tokio::net::lookup_host((auth.host(), port))
        .await?
        .next()
        .ok_or("dns found no addresses")?;

    info!("DNS lookup for {:?}: {:?}", uri, addr);

    // create quinn client endpoint

    // load CA certificates stored in the system
    let mut roots = rustls::RootCertStore::empty();
    match rustls_native_certs::load_native_certs() {
        Ok(certs) => {
            for cert in certs {
                if let Err(e) = roots.add(cert) {
                    error!("failed to parse trust anchor: {}", e);
                }
            }
        }
        Err(e) => {
            error!("couldn't load any default trust roots: {}", e);
        }
    };

    // load certificate of CA who issues the server certificate
    // NOTE that this should be used for dev only
    let ca = std::fs::read(opt.ca).expect("failed to read CA certificate");
    if let Err(e) = roots.add(CertificateDer::from(ca)) {
        error!("failed to parse trust anchor: {}", e);
    }

    let quic_client = ::quic::QuicClient::bind(opt.binds)
        .with_root_certificates(roots)
        .without_cert()
        .with_keylog(opt.key_log_file)
        .with_alpn([ALPN.into()])
        .build();

    let conn = quic_client.connect(auth.host(), addr)?;

    // create h3 client

    // h3 is designed to work with different QUIC implementations via
    // a generic interface, that is, the [`quic::Connection`] trait.
    // h3_quinn implements the trait w/ quinn to make it work with h3.
    info!("Handshaking");
    let gm_quic_conn = h3_shim::QuicConnection::new(conn).await;
    info!("QUIC connection established");

    let (mut conn, mut send_request) = h3::client::new(gm_quic_conn).await?;

    let driver = async move {
        future::poll_fn(|cx| conn.poll_close(cx)).await?;
        // tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        Ok::<_, Box<dyn std::error::Error + 'static + Send + Sync>>(())
    };

    // In the following block, we want to take ownership of `send_request`:
    // the connection will be closed only when all `SendRequest`s instances
    // are dropped.
    //
    //             So we "move" it.
    //                  vvvv
    let request = async move {
        info!("sending request ...");

        let req = http::Request::builder().uri(uri).body(())?;

        // sending request results in a bidirectional stream,
        // which is also used for receiving response
        let mut stream = send_request.send_request(req).await?;

        // finish on the sending side
        info!("waiting for peer to receive the request");
        stream.finish().await?;

        info!("receiving response ...");

        let resp = stream.recv_response().await?;

        info!("response: {:?} {}", resp.version(), resp.status());
        info!("headers: {:#?}", resp.headers());

        // `recv_data()` must be called after `recv_response()` for
        // receiving potential response body
        while let Some(mut chunk) = stream.recv_data().await? {
            let mut out = tokio::io::stdout();
            out.write_all_buf(&mut chunk).await?;
            out.flush().await?;
        }

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        Ok::<_, Box<dyn std::error::Error + 'static + Send + Sync>>(())
    };

    let derive = tokio::spawn(driver);
    let request = tokio::spawn(request);

    #[allow(clippy::question_mark)]
    if let Err(e) = derive.await? {
        return Err(e);
    }
    #[allow(clippy::question_mark)]
    if let Err(e) = request.await? {
        return Err(e);
    }

    // _ = request.await?;

    // wait for the connection to be closed before exiting
    Ok(())
}
