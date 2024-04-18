use super::{recver::ArcRecver, Recver};
use bytes::Bytes;
use std::{
    future::Future,
    ops::DerefMut,
    pin::Pin,
    task::{Context, Poll},
};

pub struct Incoming(ArcRecver);

impl Incoming {
    pub fn recv(&mut self, offset: u64, buf: Bytes) {
        let mut recver = self.0.lock().unwrap();
        let inner = recver.deref_mut();
        let holder = std::mem::take(inner);
        match holder {
            Recver::Recv(mut r) => {
                r.recv(offset, buf);
                inner.replace(Recver::Recv(r));
            }
            Recver::SizeKnown(mut r) => {
                r.recv(offset, buf);
                if r.is_all_rcvd() {
                    inner.replace(Recver::DataRecvd(r.data_recvd()));
                } else {
                    inner.replace(Recver::SizeKnown(r));
                }
            }
            other => {
                println!("ignored from {offset} len {}", buf.len());
                inner.replace(other);
            }
        }
    }

    pub fn end(&mut self, final_size: u64) {
        let mut recver = self.0.lock().unwrap();
        let inner = recver.deref_mut();
        let holder = std::mem::take(inner);
        match holder {
            Recver::Recv(r) => {
                inner.replace(Recver::SizeKnown(r.determin_size(final_size)));
            }
            other => {
                println!("there is sth wrong, ignored finish");
                inner.replace(other);
            }
        }
    }

    pub fn recv_reset(&mut self) {
        let mut recver = self.0.lock().unwrap();
        let inner = recver.deref_mut();
        let holder = std::mem::take(inner);
        match holder {
            Recver::Recv(r) => {
                r.recv_reset();
                inner.replace(Recver::ResetRecvd);
            }
            Recver::SizeKnown(r) => {
                r.recv_reset();
                inner.replace(Recver::ResetRecvd);
            }
            other => {
                println!("there is sth wrong, ignored recv_reset");
                inner.replace(other);
            }
        }
    }

    pub fn is_stopped(&mut self) -> IncomingStop<'_> {
        IncomingStop { inner: self }
    }

    pub fn window_update(&mut self) -> WindowUpdate<'_> {
        WindowUpdate { inner: self }
    }
}

pub struct WindowUpdate<'a> {
    inner: &'a Incoming,
}

impl<'a> Future for WindowUpdate<'a> {
    type Output = u64;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut recver = self.inner.0.lock().unwrap();
        let inner = recver.deref_mut();
        let holder = std::mem::take(inner);
        match holder {
            Recver::Recv(mut r) => {
                let result = r.poll_window_update(cx);
                inner.replace(Recver::Recv(r));
                result
            }
            other => {
                inner.replace(other);
                Poll::Pending
            }
        }
    }
}

pub struct IncomingStop<'a> {
    inner: &'a Incoming,
}

impl<'a> Future for IncomingStop<'a> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut recver = self.inner.0.lock().unwrap();
        let inner = recver.deref_mut();
        let holder = std::mem::take(inner);
        match holder {
            Recver::Recv(mut r) => {
                let result = r.poll_stop(cx);
                inner.replace(Recver::Recv(r));
                result
            }
            Recver::SizeKnown(mut r) => {
                let result = r.poll_stop(cx);
                inner.replace(Recver::SizeKnown(r));
                result
            }
            other => {
                inner.replace(other);
                Poll::Pending
            }
        }
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}