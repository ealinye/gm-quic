use std::{
    future::Future,
    io::{self, IoSlice},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, LazyLock, OnceLock},
    task::{ready, Context, Poll},
};

use bytes::BytesMut;
use dashmap::DashMap;
use deref_derive::Deref;
use futures::stream::BoxStream;
use tokio::task::JoinHandle;

use crate::path::Pathway;

pub trait ControlSocket: Send + Sync {
    /// Poll send the datagrams via the given pathway.
    fn poll_send_via(
        &self,
        cx: &mut Context,
        iovecs: &[IoSlice],
        pathway: Pathway,
    ) -> Poll<io::Result<usize>>;

    fn local_addr(&self) -> io::Result<SocketAddr>;

    fn recv_datagrams(&self) -> BoxStream<'_, io::Result<(BytesMut, Pathway)>>;
}

#[cfg(not(gm_quic_no_qudp))]
mod default_impl {
    use super::*;

    impl super::ControlSocket for qudp::UdpSocketController {
        fn poll_send_via(
            &self,
            cx: &mut Context,
            iovecs: &[IoSlice],
            pathway: Pathway,
        ) -> Poll<io::Result<usize>> {
            use qcongestion::MSS;
            // todo: append relay hdr
            let hdr = qudp::PacketHeader {
                src: pathway.local_addr(),
                dst: pathway.dst_addr(),
                ttl: 64,
                ecn: None,
                seg_size: MSS as u16,
                gso: true,
            };
            self.poll_send(iovecs, &hdr, cx)
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            self.local_addr()
        }

        fn recv_datagrams(&self) -> BoxStream<'_, io::Result<(BytesMut, Pathway)>> {
            struct Receiver<'u> {
                inner: qudp::Receiver<'u>,
                read: usize,
                rcvd: usize,
            }

            impl futures::Stream for Receiver<'_> {
                type Item = io::Result<(BytesMut, Pathway)>;

                fn poll_next(
                    self: Pin<&mut Self>,
                    cx: &mut Context<'_>,
                ) -> Poll<Option<Self::Item>> {
                    let this = self.get_mut();
                    if this.read == this.rcvd {
                        this.read = 0;
                        this.rcvd = 0;
                    }
                    if this.rcvd == 0 {
                        debug_assert!(this.read == 0);
                        this.rcvd = ready!(this.inner.poll_recv(cx))?;
                        // im not ensure about this
                        // if this.rcvd == 0 {
                        //     log::warn!("it seems enter the unreachable code");
                        // }
                    }

                    let hdr = &this.inner.headers[this.read];
                    let buf = &this.inner.iovecs[this.read][..hdr.seg_size as _];
                    this.read += 1;

                    let buf = BytesMut::from(buf);
                    let pathway = Pathway::Direct {
                        local: hdr.dst,
                        remote: hdr.src,
                    };
                    Poll::Ready(Some(Ok((buf, pathway))))
                }
            }

            Box::pin(Receiver {
                inner: self.receiver(),
                read: 0,
                rcvd: 0,
            })
        }
    }

    pub fn bind(addr: SocketAddr) -> io::Result<Arc<dyn ControlSocket>> {
        let usc = qudp::UdpSocketController::new(addr)?;
        Ok(Arc::new(usc))
    }
}

#[cfg(gm_quic_no_qudp)]
mod default_impl {
    use super::*;

    pub fn bind(_addr: SocketAddr) -> io::Result<Arc<dyn ControlSocket>> {
        unimplemented!("qudp(the default udp socket controller implementation) is not enabled, you must enable it by feature `qudp` or set your own implementation by `set_usc_impl`");
    }
}

#[derive(Debug, Clone, Copy)]
pub struct UscImpl {
    pub bind: fn(SocketAddr) -> io::Result<Arc<dyn ControlSocket>>,
}

static USC_IMPL: OnceLock<UscImpl> = OnceLock::new();

impl UscImpl {
    const DEFAULT: Self = Self {
        bind: default_impl::bind,
    };

    /// Install the custom usc implementation.
    ///
    /// Note that the custom usc implementation will be used globally, and it will be used to create all the [`ArcUsc`]s.
    ///
    /// You can only set the custom usc implementation once, and it must be set before any [`ArcUsc`] is created, or the
    /// default usc implementation will be used.
    pub fn install(self) {
        USC_IMPL
            .set(self)
            .expect("the custom usc implementation is already set");
    }

    fn get() -> &'static Self {
        USC_IMPL.get_or_init(|| Self::DEFAULT)
    }
}

/// 全局的usc注册管理，用于查找已有的usc，key是绑定的本地地址，包括v4和v6的地址
static USC_REGISTRY: LazyLock<DashMap<SocketAddr, (ArcUsc, JoinHandle<()>)>> =
    LazyLock::new(DashMap::new);

/// A interface to get or create the [`ArcUsc`] that corresponding to local udp socket.
pub struct UscRegistry;

impl UscRegistry {
    /// Get the exist [`ArcUsc`] which bound the given [`SocketAddr`], or crate one.
    ///
    /// The `recv_task` generate a future task to receive and process datagrams from the udp socket,
    /// the task spawned must take the ownership of the [`ArcUsc`], and dont drop it until a udp error
    /// occur.
    ///
    /// When the [`ArcUsc`] is no longer used, the task spawned will be aborted, and the bound address
    /// will be free automatically.
    ///
    /// For client, when all of the connections which use the address are closed, the [`ArcUsc`] will
    /// be dropped, the spawned task will be aborted, bound address will be free.
    ///
    /// For server, the address will not be freed until the address is unbined by server, or the server
    /// is closed.
    pub fn get_or_create_usc<Task, F>(addr: SocketAddr, recv_task: F) -> io::Result<ArcUsc>
    where
        Task: Future<Output = ()> + Send + 'static,
        F: FnOnce(ArcUsc) -> Task,
    {
        if let Some((usc, ..)) = USC_REGISTRY.get(&addr).as_deref() {
            return Ok(usc.clone());
        }

        let usc = (UscImpl::get().bind)(addr)?;
        let addr = usc.local_addr()?;

        let usc = ArcUsc { usc, addr };

        let recv_task = tokio::spawn(recv_task(usc.clone()));
        USC_REGISTRY.insert(addr, (usc.clone(), recv_task));

        Ok(usc)
    }
}

/// A wrapper around the [`UdpSocketController`] that can be shared across threads.
///
/// This struct also provide useful methods to send datagrams via a given [`Pathway`].
///
/// [`UdpSocketController`]: qudp::UdpSocketController
#[derive(Clone, Deref)]
pub struct ArcUsc {
    #[deref]
    usc: Arc<dyn ControlSocket>,
    addr: SocketAddr,
}

impl ArcUsc {
    /// Send all the datagrams via the given pathway.
    ///
    /// The returned future completes when all the datagrams are sent, or an error occurs(or occured)
    /// on udp socket.
    pub fn send_all_via_pathway<'s>(
        &'s self,
        iovecs: &'s [IoSlice<'s>],
        pathway: Pathway,
    ) -> SendAllViaPathWay<'s> {
        SendAllViaPathWay {
            usc: self,
            iovecs,
            pathway,
        }
    }
}

impl Drop for ArcUsc {
    fn drop(&mut self) {
        // 3 = self, registry, recv_task
        if Arc::strong_count(&self.usc) == 3 {
            // is possible that: recv_task is complete because usc error
            //                   or, while this drop is called, another drop is called,
            // so, pattern matching is necessary here, expect will panic
            if let Some((_addr, (_usc, recvtask))) = USC_REGISTRY.remove(&self.addr) {
                recvtask.abort();
            }
        }
    }
}

/// A future that send all the datagrams via the given pathway.
///
/// The future completes when all the datagrams are sent, or an error occurs(or occured) on udp socket.
pub struct SendAllViaPathWay<'s> {
    usc: &'s ArcUsc,
    iovecs: &'s [IoSlice<'s>],
    pathway: Pathway,
}

impl Unpin for SendAllViaPathWay<'_> {}

impl Future for SendAllViaPathWay<'_> {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let iovecs = &mut this.iovecs;
        while !iovecs.is_empty() {
            let send_once = this.usc.poll_send_via(cx, iovecs, this.pathway);
            let n = ready!(send_once)?;
            *iovecs = &iovecs[n..];
        }
        Poll::Ready(Ok(()))
    }
}
