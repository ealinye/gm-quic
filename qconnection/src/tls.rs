use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
};

use futures::channel::mpsc;
use qbase::{
    config::{
        ext::{be_parameters, WriteParameters},
        Parameters,
    },
    packet::keys::{ArcKeys, ArcOneRttKeys},
};
use qrecovery::{space::Epoch, streams::crypto::CryptoStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// write_tls_msg()，将明文数据写入tls_conn，同步的，可能会唤醒read数据发送
/// poll_read_tls_msg()，从tls_conn读取数据，异步的，返回(Vec<u8>, Option<KeyChange>)
#[derive(Debug)]
pub(crate) struct RawTlsSession {
    tls_conn: rustls::quic::Connection,
    wants_write: Option<Waker>,
}

impl RawTlsSession {
    fn new_client(
        server_name: rustls::pki_types::ServerName<'static>,
        client_params: &Parameters,
    ) -> Self {
        let config =
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth();

        let mut params = Vec::new();
        params.put_parameters(client_params);

        let connection = rustls::quic::Connection::Client(
            rustls::quic::ClientConnection::new(
                Arc::new(config),
                rustls::quic::Version::V1,
                server_name,
                params,
            )
            .unwrap(),
        );
        Self {
            tls_conn: connection,
            wants_write: None,
        }
    }

    pub fn new_server(
        cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
        key_der: rustls::pki_types::PrivateKeyDer<'static>,
        server_params: &Parameters,
    ) -> Self {
        let config = rustls::ServerConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key_der)
        .unwrap();

        let mut params = Vec::new();
        params.put_parameters(server_params);

        let connection = rustls::quic::Connection::Server(
            rustls::quic::ServerConnection::new(
                Arc::new(config),
                rustls::quic::Version::V1,
                params,
            )
            .unwrap(),
        );
        Self {
            tls_conn: connection,
            wants_write: None,
        }
    }

    // 将plaintext中的数据写入tls_conn供其处理
    fn write_tls_msg(&mut self, plaintext: &[u8]) -> Result<(), rustls::Error> {
        // rusltls::quic::Connection::read_hs()，该函数即消费掉plaintext的数据给到tls_conn内部处理
        self.tls_conn.read_hs(plaintext)?;
        if self.tls_conn.wants_write() {
            if let Some(waker) = self.wants_write.take() {
                waker.wake();
            }
        }
        Ok(())
    }

    // 轮询tls_conn，看是否有数据要从中读取并发送给对方，或者密钥升级。如果什么都没发生，则返回Pending
    fn poll_read_tls_msg(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<(Vec<u8>, Option<rustls::quic::KeyChange>)> {
        let mut buf = Vec::with_capacity(1200);
        // rusltls::quic::Connection::write_hs()，该函数即将tls_conn内部的数据写入到buf中
        let key_change = self.tls_conn.write_hs(&mut buf);
        if key_change.is_none() && buf.is_empty() {
            self.wants_write = Some(cx.waker().clone());
            return Poll::Pending;
        }

        Poll::Ready((buf, key_change))
    }
}

#[derive(Debug, Clone)]
pub struct ArcTlsSession(Arc<Mutex<RawTlsSession>>);

impl ArcTlsSession {
    pub fn new_client(
        server_name: rustls::pki_types::ServerName<'static>,
        client_params: &Parameters,
    ) -> Self {
        Self(Arc::new(Mutex::new(RawTlsSession::new_client(
            server_name,
            client_params,
        ))))
    }

    pub fn new_server(
        cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
        key_der: rustls::pki_types::PrivateKeyDer<'static>,
        server_params: &Parameters,
    ) -> Self {
        Self(Arc::new(Mutex::new(RawTlsSession::new_server(
            cert_chain,
            key_der,
            server_params,
        ))))
    }

    fn lock_guard(&self) -> MutexGuard<'_, RawTlsSession> {
        self.0.lock().unwrap()
    }

    pub fn write_tls_msg(&self, plaintext: &[u8]) -> Result<(), rustls::Error> {
        self.lock_guard().write_tls_msg(plaintext)
    }

    pub fn read_tls_msg(&self) -> ReadTlsMsg {
        ReadTlsMsg(self.clone())
    }

    /// 自托管密钥升级
    pub fn keys_upgrade(
        &self,
        crypto_streams: [&CryptoStream; 3],
        handshake_keys: ArcKeys,
        one_rtt_keys: ArcOneRttKeys,
        parameters_entry: mpsc::Sender<Parameters>,
    ) {
        // 在此创建reader任务
        for epoch in Epoch::iter() {
            let mut crypto_stream_reader = crypto_streams[*epoch].reader();
            let tls_session = self.clone();
            let mut parameters_entry = parameters_entry.clone();
            tokio::spawn(async move {
                // 不停地从crypto_stream_reader读取数据，读到就送给tls_conn
                let mut buf = Vec::with_capacity(1200);
                // TODO: 处理错误，以及何时终止？reader被销毁的时候，会终止吗？处理它们的异常终止
                // 还有任务结束但是还是没有得到传输参数的情况
                loop {
                    buf.truncate(0);
                    let _err = crypto_stream_reader.read(&mut buf).await;
                    let _err = tls_session.write_tls_msg(&buf);
                    if let Some(params) = tls_session.get_transport_parameters() {
                        _ = parameters_entry.try_send(params);
                    }
                }
            });
        }

        // 在此创建不停地检查tls_conn是否有数据要给到对方，或者产生了密钥升级
        // TODO: 处理错误，处理它们的异常终止
        tokio::spawn({
            let tls_session = self.clone();
            let mut crypto_stream_writers = [
                crypto_streams[0].writer(),
                crypto_streams[1].writer(),
                crypto_streams[2].writer(),
            ];
            async move {
                // rustls严格限制了tls握手过程中的其中各类消息的发送顺序，这就是由read_tls_msg函数的顺序调用的返回
                // 值保证的。因此，其返回了密钥升级，则需要升级到相应密级，然后后续的数据都将在新密级下发送。
                let mut epoch = Epoch::Initial;
                loop {
                    let (buf, key_upgrade) = tls_session.read_tls_msg().await;
                    if let Some(key_change) = key_upgrade {
                        match key_change {
                            rustls::quic::KeyChange::Handshake { keys } => {
                                handshake_keys.set_keys(keys);
                                epoch = Epoch::Handshake;
                            }
                            rustls::quic::KeyChange::OneRtt { keys, next } => {
                                one_rtt_keys.set_keys(keys, next);
                                // epoch = Epoch::Data;
                                break;
                            }
                        }
                    }

                    if !buf.is_empty() {
                        let _err = crypto_stream_writers[epoch].write(&buf).await;
                    }
                }
            }
        });
    }

    fn get_transport_parameters(&self) -> Option<Parameters> {
        let tls_session = self.lock_guard();
        let raw = tls_session.tls_conn.quic_transport_parameters()?;
        be_parameters(raw).ok().map(|(_, p)| p)
    }
}

pub struct ReadTlsMsg(ArcTlsSession);

impl Future for ReadTlsMsg {
    type Output = (Vec<u8>, Option<rustls::quic::KeyChange>);

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.lock_guard().poll_read_tls_msg(cx)
    }
}
