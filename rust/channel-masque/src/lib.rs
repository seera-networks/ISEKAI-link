use std::{
    convert::Infallible,
    fmt,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Buf, BytesMut};

use futures::{
    future::{BoxFuture, FutureExt},
    stream::StreamExt,
};
use hyper::{
    Request, Response, Uri,
    body::{Body, Bytes},
    rt::Executor,
};
use tower::{
    Service,
    buffer::{Buffer, future::ResponseFuture as BufferResponseFuture},
    util::BoxService,
};

use h3::ext::Protocol;
use h3::quic::StreamId;
use h3_datagram::{
    datagram_handler::HandleDatagramsExt,
    quic_traits::{DatagramConnectionExt, RecvDatagram},
};
use h3_util::client_body;
use h3_util::{client::H3Connector, client_body::H3IncomingClient, executor::SharedExec};
use http::Method;

use http_body::Frame;
use http_body_util::{BodyDataStream, StreamBody};
use tokio::sync::Mutex;
use tokio_stream::wrappers::ReceiverStream;
pub mod masque;

const DEFAULT_BUFFER_SIZE: usize = 1024;

pub fn decode_var_int(data: &[u8]) -> Option<(u64, &[u8])> {
    if data.is_empty() {
        return None;
    }
    // The length of variable-length integers is encoded in the
    // first two bits of the first byte.
    let mut v: u64 = data[0].into();
    let prefix = v >> 6;
    let length = 1 << prefix;

    if data.len() < length {
        return None;
    }
    // Once the length is known, remove these bits and read any
    // remaining bytes.
    v &= 0x3f;
    for v1 in data.iter().take(length).skip(1) {
        v = (v << 8) + Into::<u64>::into(*v1);
    }

    Some((v, &data[length..]))
}

pub fn encode_var_int(mut v: u64) -> Vec<u8> {
    let length = if v < 0x40 {
        1
    } else if v < 0x4000 {
        2
    } else if v < 0x400000 {
        4
    } else {
        8
    };
    let prefix = match length {
        1 => 0b00,
        2 => 0b01,
        4 => 0b10,
        8 => 0b11,
        _ => unreachable!(),
    };
    let mut buf = Vec::with_capacity(length);
    for _ in 1..length {
        buf.push((v & 0xff) as u8);
        v >>= 8;
    }
    buf.push(((prefix << 6) as u8) | (v & 0x3f) as u8);
    buf.reverse();
    buf
}

/// Cloneable http3 client channel, which can be used to enable multiplexing requests.
pub struct H3Channel<C, B>
where
    C: H3Connector,
    B: Body + Send + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<h3_util::Error> + Send,
{
    #[allow(clippy::type_complexity)]
    svc: Buffer<
        Request<B>,
        BoxFuture<'static, Result<Response<H3IncomingClient<C::RS, Bytes>>, h3_util::Error>>,
    >,
}

impl<C, B> Clone for H3Channel<C, B>
where
    C: H3Connector,
    B: Body + Send + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<h3_util::Error> + Send,
{
    fn clone(&self) -> Self {
        Self {
            svc: self.svc.clone(),
        }
    }
}

pub struct ResponseFuture<C>
where
    C: H3Connector,
{
    #[allow(clippy::type_complexity)]
    inner: BufferResponseFuture<
        BoxFuture<'static, Result<Response<H3IncomingClient<C::RS, Bytes>>, h3_util::Error>>,
    >,
}

impl<C, B> H3Channel<C, B>
where
    C: H3Connector,
    <C as H3Connector>::CONN: DatagramConnectionExt<hyper::body::Bytes>,
    <<C as H3Connector>::CONN as DatagramConnectionExt<bytes::Bytes>>::SendDatagramHandler: Send,
    <<C as H3Connector>::CONN as DatagramConnectionExt<bytes::Bytes>>::RecvDatagramHandler: Send,
    <<<C as H3Connector>::CONN as DatagramConnectionExt<bytes::Bytes>>::RecvDatagramHandler as RecvDatagram>::Buffer: Send,
    B: Body + Send + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<h3_util::Error> + Send,
{
    pub fn new(connector: C, uri: Uri, executor: Option<SharedExec>) -> Self {
        let executor = executor.unwrap_or_else(SharedExec::tokio);
        let svc = H3Connection::new(connector, uri, Some(executor.clone()));
        let (svc, worker) = Buffer::pair(svc, DEFAULT_BUFFER_SIZE);
        executor.execute(worker);
        Self { svc }
    }
}

impl<C, B> Service<Request<B>> for H3Channel<C, B>
where
    C: H3Connector,
    B: Body + Send + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<h3_util::Error> + Send,
{
    type Response = Response<H3IncomingClient<C::RS, Bytes>>;
    type Error = h3_util::Error;
    type Future = ResponseFuture<C>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Service::poll_ready(&mut self.svc, cx).map_err(h3_util::Error::from)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let inner = Service::call(&mut self.svc, req);
        ResponseFuture { inner }
    }
}

impl<C> Future for ResponseFuture<C>
where
    C: H3Connector,
{
    type Output = Result<Response<H3IncomingClient<C::RS, Bytes>>, h3_util::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.inner)
            .poll(cx)
            .map_err(h3_util::Error::from)
    }
}

impl<C, B> fmt::Debug for H3Channel<C, B>
where
    C: H3Connector,
    B: Body + Send + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<h3_util::Error> + Send,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("H3Channel").finish()
    }
}

impl<C> fmt::Debug for ResponseFuture<C>
where
    C: H3Connector,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseFuture").finish()
    }
}

/// h3 client connection, wrapping inner types for ease of use.
/// All request will be sent to the connection established using the connector.
/// Currently connector can only connect to a fixed server (to support grpc use case).
/// Expand connector to do resolve different server based on uri can be added in future.
pub struct H3Connection<C, B>
where
    C: H3Connector,
    <C as H3Connector>::CONN: DatagramConnectionExt<hyper::body::Bytes>,
    B: Body + Send + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<h3_util::Error>,
{
    #[allow(clippy::type_complexity)]
    inner: BoxService<Request<B>, Response<H3IncomingClient<C::RS, Bytes>>, h3_util::Error>,
}

impl<C, B> H3Connection<C, B>
where
    C: H3Connector,
    <C as H3Connector>::CONN: DatagramConnectionExt<hyper::body::Bytes>,
    <<C as H3Connector>::CONN as DatagramConnectionExt<bytes::Bytes>>::SendDatagramHandler: Send,
    <<C as H3Connector>::CONN as DatagramConnectionExt<bytes::Bytes>>::RecvDatagramHandler: Send,
    <<<C as H3Connector>::CONN as DatagramConnectionExt<bytes::Bytes>>::RecvDatagramHandler as RecvDatagram>::Buffer: Send,
    B: Body + Send + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<h3_util::Error> + Send,
{
    pub fn new(connector: C, uri: Uri, executor: Option<SharedExec>) -> Self {
        let executor = executor.unwrap_or_else(SharedExec::tokio);
        let sender = MasqueRequestSender::new(connector, uri, executor);
        Self {
            inner: BoxService::new(sender),
        }
    }
}

impl<C, B> Service<Request<B>> for H3Connection<C, B>
where
    C: H3Connector,
    <C as H3Connector>::CONN: DatagramConnectionExt<hyper::body::Bytes>,
    B: Body + Send + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<h3_util::Error>,
{
    type Response = Response<H3IncomingClient<C::RS, Bytes>>;
    type Error = h3_util::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Service::poll_ready(&mut self.inner, cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        self.inner.call(req)
    }
}

pub async fn send_request_inner<CONN, B>(
    req: hyper::Request<B>,
    mut send_request: h3::client::SendRequest<CONN::OS, Bytes>,
    from_quic_to_udp_tx: tokio::sync::mpsc::Sender<crate::masque::from_quic_to_udp::Message>,
    stream_id_tx: tokio::sync::mpsc::Sender<StreamId>,
    datagram_sender_rx: Arc<
        Mutex<tokio::sync::mpsc::Receiver<Box<dyn crate::masque::from_udp_to_quic::ErasedSender>>>,
    >,
    executor: &SharedExec,
) -> Result<Response<H3IncomingClient<CONN::RS, Bytes>>, h3_util::Error>
where
    CONN: H3Connector,
    B: Body + Send + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<h3_util::Error> + Send,
{
    let (parts, body) = req.into_parts();
    let head_req = hyper::Request::from_parts(parts, ());
    // send header
    tracing::trace!("sending h3 req header: {:?}", head_req);

    // send header.
    let stream = send_request.send_request(head_req).await?;

    let stream_id = stream.id();
    stream_id_tx.send(stream_id).await?;

    let Some(datagram_sender) = datagram_sender_rx.lock().await.recv().await else {
        return Err(anyhow::anyhow!("Failed to get datagram sender").into());
    };

    let (w, mut r) = stream.split();

    // Cancellation: cancel_tx is stored in H3IncomingClient.
    // When the response body is dropped, cancel_tx drops, triggering cancellation.
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();

    // Build the body send future with owned w and cancel support.
    let mut body_fut = Box::pin(client_body::send_h3_client_body::<CONN::BS, _>(
        w, body, cancel_rx,
    ));

    // Eager poll: try to complete body send without spawning a task.
    match futures::future::poll_fn(|cx| match body_fut.as_mut().poll(cx) {
        std::task::Poll::Ready(res) => std::task::Poll::Ready(Some(res)),
        std::task::Poll::Pending => std::task::Poll::Ready(None),
    })
    .await
    {
        Some(res) => {
            // Body completed synchronously — no spawn needed.
            res?;
        }
        None => {
            // Body still pending — move to background task.
            executor.execute(async move {
                if let Err(e) = body_fut.await {
                    tracing::warn!("h3 client body send failed: {e}");
                }
            });
        }
    };

    // return resp.
    tracing::trace!("recv header");
    let (resp, _) = r
        .recv_response()
        .await
        .inspect_err(|e| {
            tracing::error!("recv header error: {e}");
        })?
        .into_parts();

    let resp_body = H3IncomingClient::new(r, Some(cancel_tx));
    let mut resp = hyper::Response::from_parts(resp, resp_body);
    let (from_udp_to_quic_tx, from_udp_to_quic_rx) = tokio::sync::mpsc::channel(1024);
    let state = std::sync::Arc::new(crate::masque::ProxyState {
        from_udp_to_quic: crate::masque::from_udp_to_quic::Controller::new(from_udp_to_quic_tx),
        from_quic_to_udp: crate::masque::from_quic_to_udp::Controller::new(
            stream_id,
            from_quic_to_udp_tx,
        ),
        datagram_sender: std::sync::Mutex::new(Some(datagram_sender)),
        from_udp_to_quic_rx: std::sync::Mutex::new(Some(from_udp_to_quic_rx)),
    });
    resp.extensions_mut().insert(state);

    tracing::trace!("return resp");
    Ok(resp)
}

/// Sender that can do reconnection.
#[allow(clippy::type_complexity)]
pub struct MasqueRequestSender<CONN: H3Connector> {
    conn: CONN,
    send_request: Option<h3::client::SendRequest<CONN::OS, Bytes>>,
    stream_id_tx: Option<tokio::sync::mpsc::Sender<StreamId>>,
    datagram_sender_rx: Option<
        Arc<
            Mutex<
                tokio::sync::mpsc::Receiver<Box<dyn crate::masque::from_udp_to_quic::ErasedSender>>,
            >,
        >,
    >,
    from_quic_to_udp_tx:
        Option<tokio::sync::mpsc::Sender<crate::masque::from_quic_to_udp::Message>>,
    driver_rx: Option<tokio::sync::oneshot::Receiver<()>>,
    make_send_request_fut: Option<
        BoxFuture<
            'static,
            Result<
                (
                    h3::client::SendRequest<CONN::OS, Bytes>,
                    tokio::sync::mpsc::Sender<crate::masque::from_quic_to_udp::Message>,
                    tokio::sync::mpsc::Sender<StreamId>,
                    Arc<
                        Mutex<
                            tokio::sync::mpsc::Receiver<
                                Box<dyn crate::masque::from_udp_to_quic::ErasedSender>,
                            >,
                        >,
                    >,
                    tokio::sync::oneshot::Receiver<()>,
                ),
                h3_util::Error,
            >,
        >,
    >,
    uri: Uri,
    executor: SharedExec,
}

impl<CONN> MasqueRequestSender<CONN>
where
    CONN: H3Connector,
{
    pub fn new(conn: CONN, uri: Uri, executor: SharedExec) -> Self {
        Self {
            conn,
            send_request: None,
            from_quic_to_udp_tx: None,
            stream_id_tx: None,
            datagram_sender_rx: None,
            driver_rx: None,
            make_send_request_fut: None,
            uri,
            executor,
        }
    }
}

impl<CONN, B> tower::Service<Request<B>> for MasqueRequestSender<CONN>
where
    CONN: H3Connector,
    <CONN as H3Connector>::CONN: DatagramConnectionExt<hyper::body::Bytes>,
    <<CONN as H3Connector>::CONN as DatagramConnectionExt<bytes::Bytes>>::SendDatagramHandler: Send,
    <<CONN as H3Connector>::CONN as DatagramConnectionExt<bytes::Bytes>>::RecvDatagramHandler: Send,
    <<<CONN as H3Connector>::CONN as DatagramConnectionExt<bytes::Bytes>>::RecvDatagramHandler as RecvDatagram>::Buffer: Send,
    B: Body + Send + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<h3_util::Error> + Send,
{
    type Response = Response<H3IncomingClient<CONN::RS, Bytes>>;
    type Error = h3_util::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    /// This handles connection creation and reconnection.
    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        if let Some(rx) = &mut self.driver_rx {
            // check if the driver is still running
            match rx.try_recv() {
                Ok(()) => {
                    tracing::trace!("driver is closed, reconnecting.");
                    self.send_request = None;
                    self.driver_rx = None;
                }
                Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {
                    // driver is still running
                }
                Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                    tracing::trace!("driver is closed, reconnecting.");
                    self.send_request = None;
                    self.driver_rx = None;
                }
            }
        }

        // ready for send.
        if self.send_request.is_some() {
            tracing::trace!("exp poll_ready cache hit.");
            debug_assert!(self.make_send_request_fut.is_none());
            debug_assert!(self.driver_rx.is_some());
            return std::task::Poll::Ready(Ok(()));
        }

        if self.make_send_request_fut.is_none() {
            // start the driver in the background
            let conn = self.conn.clone();
            let executor = self.executor.clone();
            self.make_send_request_fut = Some(Box::pin(async move {
                let conn = conn.connect().await?;
                let (mut driver, send_request) = h3::client::new(conn).await?;
                let (tx, rx) = tokio::sync::oneshot::channel();
                let (from_quic_to_udp_tx, from_quic_to_udp_rx) = tokio::sync::mpsc::channel(1024);
                let datagram_reader = driver.get_datagram_reader();
                executor.execute(async move {
                    if let Err(e) =
                        crate::masque::from_quic_to_udp::thread(from_quic_to_udp_rx, datagram_reader)
                            .await
                    {
                        tracing::error!("from_quic_to_udp::thread exited with error: {e}");
                    }
                });
                let (stream_id_tx, mut stream_id_rx) = tokio::sync::mpsc::channel(1024);
                let (datagram_sender_tx, datagram_sender_rx) = tokio::sync::mpsc::channel(1);
                executor.execute(async move {
                    loop {
                        tokio::select! {
                            res = std::future::poll_fn(|cx| driver.poll_close(cx)) => {
                                tracing::trace!("h3 driver ended: {res:?}");
                                let _ = tx.send(());
                                break;
                            }
                            res = stream_id_rx.recv(), if !stream_id_rx.is_closed() => {
                                let Some(stream_id) = res else { continue };
                                tracing::trace!("datagram_sender requested for {stream_id}");
                                let datagram_sender = driver.get_datagram_sender(stream_id);
                                if let Err(_) = datagram_sender_tx.send(
                                    Box::new(datagram_sender) as
                                        Box<dyn crate::masque::from_udp_to_quic::ErasedSender>
                                    ).await {
                                    tracing::trace!("datagram_sender channel closed");
                                }
                            }
                        }
                    }
                });
                let datagram_sender_rx = Arc::new(Mutex::new(datagram_sender_rx));
                Ok((send_request, from_quic_to_udp_tx, stream_id_tx, datagram_sender_rx, rx))
            }));
        }
        self.make_send_request_fut
            .as_mut()
            .unwrap()
            .poll_unpin(cx)
            .map(|res| match res {
                Ok((send_request, from_quic_to_udp_tx, stream_id_tx, datagram_sender_rx, rx)) => {
                    self.send_request = Some(send_request);
                    self.from_quic_to_udp_tx = Some(from_quic_to_udp_tx);
                    self.stream_id_tx = Some(stream_id_tx);
                    self.datagram_sender_rx = Some(datagram_sender_rx);
                    self.driver_rx = Some(rx);
                    self.make_send_request_fut = None;
                    Ok(())
                }
                Err(e) => {
                    self.make_send_request_fut = None;
                    Err(e)
                }
            })
    }

    /// Gets the send_request from the cache and send the request.
    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        let (
            Some(send_request),
            Some(from_quic_to_udp_tx),
            Some(stream_id_tx),
            Some(datagram_sender_rx),
        ) = (
            self.send_request.clone(),
            self.from_quic_to_udp_tx.clone(),
            self.stream_id_tx.clone(),
            self.datagram_sender_rx.clone(),
        )
        else {
            return Box::pin(async {
                Err(anyhow::anyhow!(
                    "masque request sender called with uninitialized state; poll_ready must complete before call"
                )
                .into())
            });
        };

        // replace the uri
        let uri = &self.uri;
        let Some(scheme) = uri.scheme().cloned() else {
            return Box::pin(async {
                Err(anyhow::anyhow!("masque request sender base URI is missing a scheme").into())
            });
        };
        let Some(authority) = uri.authority().cloned() else {
            return Box::pin(async {
                Err(anyhow::anyhow!("masque request sender base URI is missing an authority").into())
            });
        };
        let Some(path_and_query) = req.uri().path_and_query().cloned() else {
            return Box::pin(async {
                Err(anyhow::anyhow!("request URI is missing a path and query").into())
            });
        };
        // fix up uri with full uri.
        let uri2 = match Uri::builder()
            .scheme(scheme)
            .authority(authority)
            .path_and_query(path_and_query)
            .build()
        {
            Ok(uri) => uri,
            Err(e) => {
                return Box::pin(async move {
                    Err(anyhow::anyhow!("failed to build request URI: {e}").into())
                });
            }
        };
        *req.uri_mut() = uri2;
        let executor = self.executor.clone();
        Box::pin(async move { send_request_inner::<CONN, B>(req, send_request, from_quic_to_udp_tx, stream_id_tx, datagram_sender_rx, &executor).await })
    }
}

pub struct MasqueClient<S, RespBody, ReqBodyErr = Infallible>
where
    S: Service<
            Request<StreamBody<ReceiverStream<Result<Frame<Bytes>, ReqBodyErr>>>>,
            Response = Response<RespBody>,
            Error = h3_util::Error,
        >,
    ReqBodyErr: Into<h3_util::Error> + Send + Sync + 'static,
    RespBody: Body<Data = Bytes> + Send + 'static + Unpin,
    RespBody::Error: Send + 'static + fmt::Debug,
{
    channel: S,
    executor: SharedExec,
    phantom: std::marker::PhantomData<(RespBody, ReqBodyErr)>,
}

#[derive(Debug, Clone)]
pub enum MasqueClientMode {
    /// Forward mode: the client will forward traffic to the specified address.
    Forward(SocketAddr),
    /// WebRTC mode
    WebRTC,
}

#[derive(Debug, Clone)]
pub enum MasqueClientEvent {
    PublicAddresses(Vec<SocketAddr>),
    NewRemoteHost(SocketAddr, SocketAddr), // (remote_addr, mapped_remote_addr)
    ResponseBodyEnded,
    ResponseBodyReceiveError(String),
    NotificationChannelClosed,
    SocketRegistrationFailed {
        remote_addr: SocketAddr,
        error: String,
    },
    ContextIdRegistrationFailed {
        context_id: u64,
        remote_addr: SocketAddr,
        stage: ContextIdRegistrationStage,
        error: String,
    },
    CompressionAssignSendFailed {
        context_id: u64,
        remote_addr: SocketAddr,
        error: String,
    },
}

#[derive(Debug, Clone, Copy)]
pub enum ContextIdRegistrationStage {
    FromQuicToUdp,
    FromUdpToQuic,
}

impl<S, RespBody, ReqBodyErr> MasqueClient<S, RespBody, ReqBodyErr>
where
    S: Service<
            Request<StreamBody<ReceiverStream<Result<Frame<Bytes>, ReqBodyErr>>>>,
            Response = Response<RespBody>,
            Error = h3_util::Error,
        >,
    ReqBodyErr: Into<h3_util::Error> + Send + Sync + 'static,
    RespBody: Body<Data = Bytes> + Send + 'static + Unpin,
    RespBody::Error: Send + 'static + fmt::Debug,
{
    pub fn new(inner: S, executor: Option<SharedExec>) -> Self {
        Self {
            channel: inner,
            executor: executor.unwrap_or_else(SharedExec::tokio),
            phantom: std::marker::PhantomData,
        }
    }

    pub async fn start(
        &mut self,
        mode: MasqueClientMode,
    ) -> Result<tokio::sync::mpsc::Receiver<MasqueClientEvent>, h3_util::Error> {
        self.start_impl(mode).await
    }

    async fn start_impl(
        &mut self,
        mode: MasqueClientMode,
    ) -> Result<tokio::sync::mpsc::Receiver<MasqueClientEvent>, h3_util::Error> {
        let (req_body_tx, req_body_rx): (
            tokio::sync::mpsc::Sender<Result<Frame<Bytes>, ReqBodyErr>>,
            tokio::sync::mpsc::Receiver<Result<Frame<Bytes>, ReqBodyErr>>,
        ) = tokio::sync::mpsc::channel(1);
        let req_build = Request::builder()
            .method(Method::CONNECT)
            .uri("/.well-known/masque/udp/%2A/%2A/")
            .header("connect-udp-bind", "?1")
            .header("capsule-protocol", "?1")
            .extension(Protocol::CONNECT_UDP);
        let req_build = if let MasqueClientMode::WebRTC = &mode {
            req_build.header("seera-session-create", "?1")
        } else {
            req_build
        };
        let req = req_build.body(StreamBody::new(ReceiverStream::new(req_body_rx)))?;
        // wait for ready
        futures::future::poll_fn(|cx| self.channel.poll_ready(cx)).await?;
        let mut resp = self.channel.call(req).await?;

        resp.status().is_success().then(|| ()).ok_or_else(|| {
            anyhow::anyhow!("CONNECT request failed with status: {}", resp.status())
        })?;

        let Some(proxy_state) = resp
            .extensions_mut()
            .remove::<std::sync::Arc<crate::masque::ProxyState>>()
        else {
            tracing::warn!("missing ProxyState in request extensions");
            return Err(anyhow::anyhow!("missing ProxyState in request extensions").into());
        };
        // Extract the datagram sender and channel receiver that were placed in ProxyState
        // by the H3 transport layer. Both are consumed exactly once, here, after
        // authentication has succeeded. The guards are scoped to ensure they are
        // dropped before `proxy_state` is used further below.
        let datagram_sender = {
            let mut guard = proxy_state
                .datagram_sender
                .lock()
                .map_err(|_| anyhow::anyhow!("datagram_sender mutex poisoned"))?;
            guard.take()
        };
        let from_udp_to_quic_rx = {
            let mut guard = proxy_state
                .from_udp_to_quic_rx
                .lock()
                .map_err(|_| anyhow::anyhow!("from_udp_to_quic_rx mutex poisoned"))?;
            guard.take()
        };
        let (datagram_sender, from_udp_to_quic_rx) = match (datagram_sender, from_udp_to_quic_rx) {
            (Some(s), Some(r)) => (s, r),
            _ => {
                tracing::warn!("datagram_sender or from_udp_to_quic_rx already consumed");
                return Err(anyhow::anyhow!(
                    "datagram_sender or from_udp_to_quic_rx already consumed"
                )
                .into());
            }
        };

        // Spawn the UDP-to-QUIC forwarding thread now that authentication has passed.
        self.executor.execute(async move {
            if let Err(e) =
                crate::masque::from_udp_to_quic::thread(from_udp_to_quic_rx, datagram_sender).await
            {
                tracing::error!("from_udp_to_quic::thread exited with error: {e}");
            }
        });

        let mut notification_rx_from_quic = match proxy_state
            .from_quic_to_udp
            .register_stream_id(mode.clone())
            .await
        {
            Ok(res) => res,
            Err(e) => {
                tracing::error!("Failed to register socket to from_quic_to_udp: {e}");
                return Err(
                    anyhow::anyhow!("Failed to register socket to from_quic_to_udp: {e}").into(),
                );
            }
        };

        let mut context_id = 1u64;

        match proxy_state
            .from_quic_to_udp
            .register_context_id(context_id, None)
            .await
        {
            Ok(res) => res,
            Err(e) => {
                tracing::error!("Failed to register context_id={}: {e}", context_id);
                return Err(
                    anyhow::anyhow!("Failed to register context_id={}: {e}", context_id).into(),
                );
            }
        }

        let mut notification_rx_from_udp = match proxy_state.from_udp_to_quic.start().await {
            Ok(res) => res,
            Err(e) => {
                tracing::error!("Failed to start from_udp_to_quic: {e}");
                return Err(anyhow::anyhow!("Failed to start from_udp_to_quic: {e}").into());
            }
        };

        match proxy_state
            .from_udp_to_quic
            .register_context_id(context_id, None)
            .await
        {
            Ok(res) => res,
            Err(e) => {
                tracing::error!("Failed to register context_id={}: {e}", context_id);
                return Err(
                    anyhow::anyhow!("Failed to register context_id={}: {e}", context_id).into(),
                );
            }
        }

        let capsule = build_compression_assign_capsule(context_id, None);
        req_body_tx.send(Ok(Frame::data(capsule))).await?;

        let public_addrs = resp
            .headers()
            .get("proxy-public-address")
            .and_then(|value| value.to_str().ok())
            .and_then(|s| {
                Some(
                    s.split(',')
                        .filter_map(|v| v.parse::<SocketAddr>().ok())
                        .collect::<Vec<_>>(),
                )
            })
            .ok_or_else(|| anyhow::anyhow!("invalid proxy-public-address header value"))?;
        if public_addrs.is_empty() {
            return Err(anyhow::anyhow!("no public address provided by server").into());
        }

        let (event_tx, event_rx) = tokio::sync::mpsc::channel(1024);

        if event_tx
            .send(MasqueClientEvent::PublicAddresses(public_addrs))
            .await
            .is_err()
        {
            tracing::debug!("event receiver dropped");
        }

        let (_, resp_body) = resp.into_parts();
        let mut resp_body = BodyDataStream::new(resp_body);

        self.executor.execute(async move {
            let mut buf = BytesMut::new();
            loop {
                tokio::select! {
                    msg = notification_rx_from_quic.recv() => {
                        match msg {
                            Some(crate::masque::from_quic_to_udp::Notification::NewSocket(socket, remote_addr, connected)) => {
                                let mapped_remote_addr = socket.local_addr().unwrap_or_else(|_| {
                                    tracing::warn!("Failed to get local address of socket, using remote address as fallback");
                                    remote_addr
                                });
                                tracing::debug!("Received notification for new client connection from {remote_addr}");
                                if let MasqueClientMode::WebRTC = &mode {
                                    let capsule = build_seera_mapped_addr_capsule(mapped_remote_addr);
                                    if let Err(e) = req_body_tx.send(Ok(Frame::data(capsule))).await {
                                        tracing::error!("Failed to send SEERA_MAPPED_ADDR capsule: {e}");
                                        if event_tx
                                            .send(MasqueClientEvent::CompressionAssignSendFailed {
                                                context_id,
                                                remote_addr,
                                                error: e.to_string(),
                                            })
                                            .await
                                            .is_err()
                                        {
                                            tracing::debug!("event receiver dropped");
                                        }
                                        continue;
                                    }
                                    tracing::info!("Sent SEERA_MAPPED_ADDR capsule for remote_addr: {remote_addr}, mapped_remote_addr: {mapped_remote_addr}");
                                }
                                if event_tx
                                    .send(MasqueClientEvent::NewRemoteHost(remote_addr, mapped_remote_addr))
                                    .await
                                    .is_err()
                                {
                                    tracing::debug!("event receiver dropped");
                                }
                                if let Err(e) = proxy_state.from_udp_to_quic.register_socket(socket.clone(), remote_addr, connected).await {
                                    tracing::error!("Failed to register socket: {e}");
                                    if event_tx
                                        .send(MasqueClientEvent::SocketRegistrationFailed {
                                            remote_addr,
                                            error: e.to_string(),
                                        })
                                        .await
                                        .is_err()
                                    {
                                        tracing::debug!("event receiver dropped");
                                    }
                                    continue;
                                }
                                context_id = context_id.saturating_add(1);

                                match proxy_state.from_quic_to_udp.register_context_id(context_id, Some(remote_addr)).await {
                                    Ok(res) => res,
                                    Err(e) => {
                                        tracing::error!("Failed to register context_id={}: {e}", context_id);
                                        if event_tx
                                            .send(MasqueClientEvent::ContextIdRegistrationFailed {
                                                context_id,
                                                remote_addr,
                                                stage: ContextIdRegistrationStage::FromQuicToUdp,
                                                error: e.to_string(),
                                            })
                                            .await
                                            .is_err()
                                        {
                                            tracing::debug!("event receiver dropped");
                                        }
                                        break;
                                    }
                                }

                                match proxy_state.from_udp_to_quic.register_context_id(context_id, Some(remote_addr)).await {
                                    Ok(res) => res,
                                    Err(e) => {
                                        tracing::error!("Failed to register context_id={}: {e}", context_id);
                                        if event_tx
                                            .send(MasqueClientEvent::ContextIdRegistrationFailed {
                                                context_id,
                                                remote_addr,
                                                stage: ContextIdRegistrationStage::FromUdpToQuic,
                                                error: e.to_string(),
                                            })
                                            .await
                                            .is_err()
                                        {
                                            tracing::debug!("event receiver dropped");
                                        }
                                        break;
                                    }
                                }

                                let capsule = build_compression_assign_capsule(context_id, Some(remote_addr));
                                if let Err(e) = req_body_tx.send(Ok(Frame::data(capsule))).await {
                                    tracing::error!("Failed to send COMPRESSION_ASSIGN capsule: {e}");
                                    if event_tx
                                        .send(MasqueClientEvent::CompressionAssignSendFailed {
                                            context_id,
                                            remote_addr,
                                            error: e.to_string(),
                                        })
                                        .await
                                        .is_err()
                                    {
                                        tracing::debug!("event receiver dropped");
                                    }
                                    continue;
                                }
                                tracing::info!("Sent COMPRESSION_ASSIGN capsule for new client connection from {remote_addr}");
                            }
                            None => {
                                tracing::info!("Notification channel closed");
                                if event_tx
                                    .send(MasqueClientEvent::NotificationChannelClosed)
                                    .await
                                    .is_err()
                                {
                                    tracing::debug!("event receiver dropped");
                                }
                                break;
                            }
                        }
                    }
                    msg = notification_rx_from_udp.recv() => {
                        match msg {
                            Some(crate::masque::from_udp_to_quic::Notification::SocketConnected(remote_addr)) => {
                                tracing::debug!("Received SocketConnected notification for new client connection from {remote_addr}");
                                match proxy_state.from_quic_to_udp.notify_socket_connected(remote_addr).await {
                                    Ok(res) => res,
                                    Err(e) => {
                                        tracing::error!("Failed to notify socket connected for remote_addr={} from quic_to_udp: {e}", remote_addr);
                                    }
                                }
                            }
                            Some(crate::masque::from_udp_to_quic::Notification::SocketDisconnected(remote_addr)) => {
                                tracing::debug!("Received SocketDisconnected notification for client connection from {remote_addr}");
                                match proxy_state.from_quic_to_udp.notify_socket_disconnected(remote_addr).await {
                                    Ok(res) => res,
                                    Err(e) => {
                                        tracing::error!("Failed to notify socket disconnected for remote_addr={} from quic_to_udp: {e}", remote_addr);
                                    }
                                }
                            }
                            Some(crate::masque::from_udp_to_quic::Notification::InvalidatedContextId(context_id)) => {
                                match proxy_state.from_quic_to_udp.unregister_context_id(context_id).await {
                                    Ok(res) => res,
                                    Err(e) => {
                                        tracing::error!("Failed to unregister context_id={} from quic_to_udp: {e}", context_id);
                                    }
                                }

                                let capsule = build_compression_assign_close_capsule(context_id);
                                if let Err(e) = req_body_tx.send(Ok(Frame::data(capsule))).await {
                                    tracing::error!("Failed to send COMPRESSION_ASSIGN_CLOSE capsule: {e}");
                                }
                                continue;
                            }
                            None => {
                                tracing::info!("Notification channel closed");
                                if event_tx
                                    .send(MasqueClientEvent::NotificationChannelClosed)
                                    .await
                                    .is_err()
                                {
                                    tracing::debug!("event receiver dropped");
                                }
                                break;
                            }
                        }
                    }
                    res = resp_body.next() => {
                        match res {
                            Some(Ok(bytes)) => {
                                buf.extend_from_slice(&bytes);
                                loop {
                                    let chunk = buf.chunk();
                                    let Some((capsule_type, after_type)) = decode_var_int(chunk) else {
                                        // incomplete capsule type
                                        break;
                                    };
                                    let capsule_type_len = chunk.len() - after_type.len();
                                    let Some((length, after_length)) = decode_var_int(after_type) else {
                                        // incomplete capsule length
                                        break;
                                    };
                                    let capsule_len_len = after_type.len() - after_length.len();
                                    let Ok(payload_len) = usize::try_from(length) else {
                                        tracing::error!("capsule payload length over usize: {}", length);
                                        return;
                                    };
                                    let Some(header_len) = capsule_type_len.checked_add(capsule_len_len)
                                    else {
                                        tracing::error!("capsule header length overflow");
                                        return;
                                    };
                                    let Some(total_len) = header_len.checked_add(payload_len) else {
                                        tracing::error!("capsule total length overflow");
                                        return;
                                    };
                                    if chunk.len() < total_len {
                                        // incomplete capsule payload
                                        break;
                                    }

                                    let payload = &chunk[header_len..total_len];
                                    match capsule_type {
                                        0x12 => {
                                            // COMPRESSION_ASSIGN_ACK capsule
                                            let Some((context_id, _)) =
                                                decode_var_int(payload)
                                            else {
                                                buf.advance(total_len);
                                                continue;
                                            };
                                            tracing::info!("Received COMPRESSION_ASSIGN_ACK for context_id={context_id}");
                                            buf.advance(total_len);
                                            continue;
                                        }
                                        0x13 => {
                                            // COMPRESSION_ASSIGN_CLOSE capsule
                                            let Some((context_id, _)) =
                                                decode_var_int(payload)
                                            else {
                                                buf.advance(total_len);
                                                continue;
                                            };
                                            tracing::info!("Received COMPRESSION_ASSIGN_CLOSE for context_id={context_id}");
                                            match proxy_state.from_udp_to_quic.unregister_context_id(context_id).await {
                                                Ok(res) => res,
                                                Err(e) => {
                                                    tracing::error!("Failed to unregister context_id={} from udp_to_quic: {e}", context_id);
                                                }
                                            }
                                            match proxy_state.from_quic_to_udp.unregister_context_id(context_id).await {
                                                Ok(res) => res,
                                                Err(e) => {
                                                    tracing::error!("Failed to unregister context_id={} from quic_to_udp: {e}", context_id);
                                                }
                                            }
                                            buf.advance(total_len);
                                            continue;
                                        }
                                        _ => {
                                            tracing::debug!("Received unknown capsule type {capsule_type}, ignoring");
                                            buf.advance(total_len);
                                            continue;
                                        }
                                    }
                                }
                            }
                            Some(Err(e)) => {
                                tracing::error!("Error receiving response body: {:?}", e);
                                if event_tx
                                    .send(MasqueClientEvent::ResponseBodyReceiveError(format!("{e:?}")))
                                    .await
                                    .is_err()
                                {
                                    tracing::debug!("event receiver dropped");
                                }
                                break;
                            }
                            None => {
                                tracing::info!("Response body stream ended");
                                if event_tx
                                    .send(MasqueClientEvent::ResponseBodyEnded)
                                    .await
                                    .is_err()
                                {
                                    tracing::debug!("event receiver dropped");
                                }
                                break;
                            }
                        }
                    }
                }
            }
        });
        Ok(event_rx)
    }
}

/// Encode a capsule as `type || length || payload` using QUIC variable-length
/// integer encoding for the type and length fields.
fn build_raw_capsule(capsule_type: u64, payload: &[u8]) -> Bytes {
    let mut buf = BytesMut::new();
    buf.extend_from_slice(&encode_var_int(capsule_type));
    buf.extend_from_slice(&encode_var_int(payload.len() as u64));
    buf.extend_from_slice(payload);
    buf.freeze()
}

/// Build a well-formed COMPRESSION_ASSIGN capsule (type `0x11`).
///
/// `addr = None`  → `ip_version = 0` (uncompressed context)  
/// `addr = Some(V4(…))` → `ip_version = 4` + 4-byte IP + 2-byte port  
/// `addr = Some(V6(…))` → `ip_version = 6` + 16-byte IP + 2-byte port
fn build_compression_assign_capsule(context_id: u64, addr: Option<SocketAddr>) -> Bytes {
    let mut payload = BytesMut::new();
    payload.extend_from_slice(&encode_var_int(context_id));
    match addr {
        None => payload.extend_from_slice(&[0u8]),
        Some(SocketAddr::V4(v4)) => {
            payload.extend_from_slice(&[4u8]);
            payload.extend_from_slice(&v4.ip().octets());
            payload.extend_from_slice(&v4.port().to_be_bytes());
        }
        Some(SocketAddr::V6(v6)) => {
            payload.extend_from_slice(&[6u8]);
            payload.extend_from_slice(&v6.ip().octets());
            payload.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    build_raw_capsule(0x11, &payload)
}

fn build_compression_assign_close_capsule(context_id: u64) -> Bytes {
    let mut payload = BytesMut::new();
    payload.extend_from_slice(&encode_var_int(context_id));
    build_raw_capsule(0x13, &payload)
}

/// Build a well-formed SEERA_CLIENT_ADDR capsule (type `0x40`).
///
/// `addr = None`  → `ip_version = 0` (uncompressed context)  
/// `addr = Some(V4(…))` → `ip_version = 4` + 4-byte IP + 2-byte port  
/// `addr = Some(V6(…))` → `ip_version = 6` + 16-byte IP + 2-byte port
fn build_seera_mapped_addr_capsule(mapped_addr: SocketAddr) -> Bytes {
    let mut payload = BytesMut::new();
    match mapped_addr {
        SocketAddr::V4(v4) => {
            payload.extend_from_slice(&[4u8]);
            payload.extend_from_slice(&v4.ip().octets());
            payload.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            payload.extend_from_slice(&[6u8]);
            payload.extend_from_slice(&v6.ip().octets());
            payload.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    build_raw_capsule(0x40, &payload)
}
