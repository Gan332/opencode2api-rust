//! A hand-rolled HTTP/1.1 client that puts every request on the wire the way
//! the official Bun-based OpenCode clients do: the same TLS hello shape, the
//! same header order, HTTP/1.1 only, and the same body decoders. Requests are
//! always read fully before they are sent, responses stream.

mod bun;

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use futures_util::Stream;
use http::header::{HeaderName, HeaderValue, ACCEPT_ENCODING, CONTENT_LENGTH};
use http::{HeaderMap, Method, StatusCode};
use rand::RngCore;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_util::io::StreamReader;
use url::Url;

pub use bun::{BUN_COMMON_HEADERS, bun_request_head};

pub const V2_CLIENT_VERSION: &str = "2.1.1";
pub const V1_CLIENT_VERSION: &str = "1.19.3";
pub const V1_BUN_VERSION: &str = "1.3.14";
pub const V1_CHAT_SDK: &str = "4.0.23";
pub const V1_RESPONSES_SDK: &str = "4.0.40";
pub const V1_ANTHROPIC_SDK: &str = "4.0.46";

pub fn v2_user_agent() -> String {
    format!("opencode/latest/{V2_CLIENT_VERSION}/cli")
}

pub fn v1_user_agent() -> String {
    format!("opencode/{V1_CLIENT_VERSION}")
}

pub fn v1_model_user_agent(provider_utils: &str) -> String {
    format!(
        "{} ai-sdk/provider-utils/{provider_utils} runtime/bun/{V1_BUN_VERSION}",
        v1_user_agent()
    )
}

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}
pub type BoxStream = Box<dyn AsyncReadWrite>;

#[async_trait::async_trait]
pub trait Dialer: Send + Sync {
    async fn dial(&self, address: &str) -> Result<BoxStream>;
}

pub struct DirectDialer {
    timeout: Duration,
}

impl DirectDialer {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

#[async_trait::async_trait]
impl Dialer for DirectDialer {
    async fn dial(&self, address: &str) -> Result<BoxStream> {
        let stream = tokio::time::timeout(self.timeout, TcpStream::connect(address))
            .await
            .map_err(|_| anyhow!("dial {address}: timeout"))?
            .with_context(|| format!("dial {address}"))?;
        let _ = stream.set_nodelay(true);
        Ok(Box::new(stream))
    }
}

#[derive(Clone)]
pub struct Request {
    pub method: Method,
    pub url: Url,
    pub headers: HeaderMap,
    pub body: Option<Bytes>,
}

impl Request {
    pub fn new(method: Method, url: Url) -> Self {
        Self {
            method,
            url,
            headers: HeaderMap::new(),
            body: None,
        }
    }

    pub fn get(url: Url) -> Self {
        Self::new(Method::GET, url)
    }

    pub fn post(url: Url) -> Self {
        Self::new(Method::POST, url)
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            self.headers.insert(name, value);
        }
        self
    }

    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(Bytes::from(body));
        self
    }

    pub fn json(mut self, value: &serde_json::Value) -> Result<Self> {
        self.headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        self.body = Some(Bytes::from(serde_json::to_vec(value)?));
        Ok(self)
    }
}

pub struct Response {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: BodyStream,
}

pub struct BodyStream {
    rx: mpsc::Receiver<Result<Bytes>>,
}

impl BodyStream {
    pub fn empty() -> Self {
        let (_tx, rx) = mpsc::channel(1);
        Self { rx }
    }

    pub async fn collect(mut self) -> Result<Bytes> {
        let mut out = Vec::new();
        while let Some(chunk) = self.rx.recv().await {
            out.extend_from_slice(&chunk?);
        }
        Ok(Bytes::from(out))
    }

    pub async fn text(self) -> Result<String> {
        Ok(String::from_utf8_lossy(&self.collect().await?).into_owned())
    }

    pub async fn next_chunk(&mut self) -> Option<Result<Bytes>> {
        self.rx.recv().await
    }
}

impl Stream for BodyStream {
    type Item = Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

#[derive(Clone)]
pub struct TransportOptions {
    pub proxy: Option<Url>,
    pub dialer: Option<Arc<dyn Dialer>>,
    pub connect_timeout: Duration,
    pub response_header_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_idle_per_host: usize,
    pub keep_alive: bool,
    pub bun: bool,
}

impl Default for TransportOptions {
    fn default() -> Self {
        Self {
            proxy: None,
            dialer: None,
            connect_timeout: Duration::from_secs(5),
            response_header_timeout: Duration::ZERO,
            idle_timeout: Duration::from_secs(120),
            max_idle_per_host: 256,
            keep_alive: true,
            bun: false,
        }
    }
}

struct IdleConn {
    stream: BoxStream,
    idle_at: Instant,
}

pub struct Transport {
    options: TransportOptions,
    tls: Arc<ClientConfig>,
    proxy_tls: Arc<ClientConfig>,
    direct: Arc<DirectDialer>,
    idle: Arc<parking_lot::Mutex<HashMap<String, Vec<IdleConn>>>>,
}

impl Transport {
    pub fn new(options: TransportOptions) -> Result<Self> {
        let proxy_tls = Arc::new(default_tls_config()?);
        let tls = Arc::new(if options.bun {
            bun::bun_tls_config()?
        } else {
            default_tls_config()?
        });
        Ok(Self {
            options,
            tls,
            proxy_tls,
            direct: Arc::new(DirectDialer::new(Duration::from_secs(30))),
            idle: Arc::new(parking_lot::Mutex::new(HashMap::new())),
        })
    }

    pub fn options(&self) -> &TransportOptions {
        &self.options
    }

    pub async fn execute(&self, request: Request) -> Result<Response> {
        let body = request.body.clone();
        let head = self.request_head(&request)?;
        let key = connection_key(&request.url);
        let mut retried = false;
        loop {
            let (stream, reused) = self.connect(&request.url, &key).await?;
            match self.exchange(stream, &head, body.as_deref()).await {
                Ok((status, headers, reader)) => {
                    let response =
                        self.spawn_body(reader, status, headers, &request, key, reused)?;
                    return Ok(response);
                }
                Err(error) => {
                    if reused && !retried {
                        retried = true;
                        continue;
                    }
                    return Err(error);
                }
            }
        }
    }

    fn request_head(&self, request: &Request) -> Result<Vec<u8>> {
        if self.options.bun {
            let (head, _) = bun_request_head(
                request.method.as_str(),
                &request.url,
                &request.headers,
                request.body.as_deref().map(|body| body.len()),
            )?;
            Ok(head)
        } else {
            regular_request_head(
                request.method.as_str(),
                &request.url,
                &request.headers,
                request.body.as_deref().map(|body| body.len()),
            )
        }
    }

    async fn connect(&self, url: &Url, key: &str) -> Result<(BoxStream, bool)> {
        while let Some(idle) = self.take_idle(key) {
            if idle.idle_at.elapsed() <= self.options.idle_timeout {
                return Ok((idle.stream, true));
            }
        }
        let stream = self.dial(url).await?;
        Ok((stream, false))
    }

    async fn dial(&self, url: &Url) -> Result<BoxStream> {
        let host = url.host_str().ok_or_else(|| anyhow!("url has no host"))?;
        let port = url.port_or_known_default().unwrap_or(443);
        let addr = format!("{host}:{port}");
        let mut stream: BoxStream = if let Some(proxy) = &self.options.proxy {
            let proxy_addr = proxy_address(proxy);
            let base: BoxStream = match &self.options.dialer {
                Some(dialer) => dialer.dial(&proxy_addr).await?,
                None => {
                    self.direct
                        .dial(&proxy_addr)
                        .await
                        .with_context(|| format!("proxy {proxy_addr}"))?
                }
            };
            self.tunnel(proxy, base, &addr).await?
        } else if let Some(dialer) = &self.options.dialer {
            dialer.dial(&addr).await?
        } else {
            tokio::time::timeout(self.options.connect_timeout, self.direct.dial(&addr))
                .await
                .map_err(|_| anyhow!("dial {addr}: timeout"))??
        };
        if url.scheme() == "https" {
            stream = self.tls_connect(host, stream).await?;
        }
        Ok(stream)
    }

    async fn tls_connect(&self, host: &str, stream: BoxStream) -> Result<BoxStream> {
        let name = ServerName::try_from(host.to_string()).map_err(|_| anyhow!("invalid tls name"))?;
        let connector = tokio_rustls::TlsConnector::from(self.tls.clone());
        let stream = tokio::time::timeout(Duration::from_secs(10), connector.connect(name, stream))
            .await
            .map_err(|_| anyhow!("tls handshake timeout"))?
            .context("tls handshake")?;
        Ok(Box::new(stream))
    }

    async fn tunnel(&self, proxy: &Url, mut stream: BoxStream, target: &str) -> Result<BoxStream> {
        let scheme = proxy.scheme().to_ascii_lowercase();
        if scheme == "https" {
            let host = proxy
                .host_str()
                .ok_or_else(|| anyhow!("proxy has no host"))?;
            let name =
                ServerName::try_from(host.to_string()).map_err(|_| anyhow!("invalid proxy name"))?;
            let connector = tokio_rustls::TlsConnector::from(self.proxy_tls.clone());
            let tls = connector
                .connect(name, stream)
                .await
                .context("proxy tls handshake")?;
            stream = Box::new(tls);
        }
        if scheme.starts_with("socks5") {
            socks5_connect(&mut stream, proxy, target).await?;
        } else {
            http_connect(&mut stream, proxy, target).await?;
        }
        Ok(stream)
    }

    async fn exchange(
        &self,
        mut stream: BoxStream,
        head: &[u8],
        body: Option<&[u8]>,
    ) -> Result<(StatusCode, HeaderMap, BufReader<BoxStream>)> {
        stream.write_all(head).await?;
        if let Some(body) = body {
            stream.write_all(body).await?;
        }
        stream.flush().await?;

        let mut reader = BufReader::new(stream);
        let result = if self.options.response_header_timeout.is_zero() {
            read_response_head(&mut reader).await
        } else {
            tokio::time::timeout(
                self.options.response_header_timeout,
                read_response_head(&mut reader),
            )
            .await
            .map_err(|_| anyhow!("timeout awaiting response headers"))?
        };
        match result {
            Ok(value) => Ok((value.0, value.1, reader)),
            Err(error) => Err(error),
        }
    }

    fn spawn_body(
        &self,
        reader: BufReader<BoxStream>,
        status: StatusCode,
        headers: HeaderMap,
        request: &Request,
        key: String,
        reusable: bool,
    ) -> Result<Response> {
        let framing = framing_for(status, &headers, request.method == Method::HEAD);
        let encoding = headers
            .get(http::header::CONTENT_ENCODING)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        let (tx, rx) = mpsc::channel(8);
        let keep_alive = self.options.keep_alive && reusable && !framing_until_eof(&framing);
        let pool = self.idle.clone();
        let idle_timeout = self.options.idle_timeout;
        let max_idle = self.options.max_idle_per_host;
        let decode = !encoding.is_empty() && encoding != "identity";

        if decode {
            let (raw_tx, mut raw_rx) = mpsc::channel::<Result<Bytes>>(8);
            let raw_key = key.clone();
            tokio::spawn(async move {
                let reusable = read_body(reader, framing, &raw_tx, keep_alive, &raw_key, pool, idle_timeout, max_idle).await;
                let _ = reusable;
            });
            let stream = StreamReader::new(ReceiverStream::new(raw_rx));
            let buffered = BufReader::new(stream);
            tokio::spawn(async move {
                let result = decode_body(encoding, buffered, &tx).await;
                if let Err(error) = result {
                    let _ = tx.send(Err(error)).await;
                }
            });
        } else {
            tokio::spawn(async move {
                read_body(reader, framing, &tx, keep_alive, &key, pool, idle_timeout, max_idle).await;
            });
        }

        let mut out_headers = headers.clone();
        if decode {
            out_headers.remove(http::header::CONTENT_ENCODING);
            out_headers.remove(http::header::CONTENT_LENGTH);
        }
        Ok(Response {
            status,
            headers: out_headers,
            body: BodyStream { rx },
        })
    }

    fn take_idle(&self, key: &str) -> Option<IdleConn> {
        let mut idle = self.idle.lock();
        let conns = idle.get_mut(key)?;
        let conn = conns.pop();
        if conns.is_empty() {
            idle.remove(key);
        }
        conn
    }

    fn put_idle(&self, key: String, stream: BoxStream) {
        let mut idle = self.idle.lock();
        let conns = idle.entry(key).or_default();
        if conns.len() >= self.options.max_idle_per_host {
            return;
        }
        conns.push(IdleConn {
            stream,
            idle_at: Instant::now(),
        });
    }

    pub fn close_idle(&self) {
        self.idle.lock().clear();
    }
}

pub struct ReceiverStream {
    rx: mpsc::Receiver<Result<Bytes>>,
}

impl ReceiverStream {
    fn new(rx: mpsc::Receiver<Result<Bytes>>) -> Self {
        Self { rx }
    }
}

impl Stream for ReceiverStream {
    type Item = std::io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(Ok(chunk))) => Poll::Ready(Some(Ok(chunk))),
            Poll::Ready(Some(Err(error))) => {
                Poll::Ready(Some(Err(std::io::Error::other(error.to_string()))))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

enum Framing {
    Empty,
    Length(usize),
    Chunked,
    UntilEof,
}

fn framing_until_eof(framing: &Framing) -> bool {
    matches!(framing, Framing::UntilEof)
}

fn framing_for(status: StatusCode, headers: &HeaderMap, head: bool) -> Framing {
    if head || status == StatusCode::NO_CONTENT || status == StatusCode::NOT_MODIFIED {
        return Framing::Empty;
    }
    if headers
        .get(http::header::TRANSFER_ENCODING)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
    {
        return Framing::Chunked;
    }
    if let Some(length) = headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<usize>().ok())
    {
        return Framing::Length(length);
    }
    Framing::UntilEof
}

async fn read_body(
    reader: BufReader<BoxStream>,
    framing: Framing,
    tx: &mpsc::Sender<Result<Bytes>>,
    keep_alive: bool,
    key: &str,
    pool: Arc<parking_lot::Mutex<HashMap<String, Vec<IdleConn>>>>,
    idle_timeout: Duration,
    max_idle: usize,
) -> bool {
    let mut reader = reader;
    let result = match framing {
        Framing::Empty => Ok(()),
        Framing::Length(mut remaining) => {
            let mut buffer = vec![0u8; 16 * 1024];
            let mut okay = Ok(());
            while remaining > 0 {
                let want = remaining.min(buffer.len());
                match reader.read(&mut buffer[..want]).await {
                    Ok(0) => {
                        okay = Err(anyhow!("unexpected end of response body"));
                        break;
                    }
                    Ok(read) => {
                        remaining -= read;
                        if tx
                            .send(Ok(Bytes::copy_from_slice(&buffer[..read])))
                            .await
                            .is_err()
                        {
                            okay = Err(anyhow!("response body dropped"));
                            break;
                        }
                    }
                    Err(error) => {
                        okay = Err(error.into());
                        break;
                    }
                }
            }
            okay
        }
        Framing::Chunked => read_chunked(&mut reader, tx).await,
        Framing::UntilEof => {
            let mut buffer = vec![0u8; 16 * 1024];
            loop {
                match reader.read(&mut buffer).await {
                    Ok(0) => break Ok(()),
                    Ok(read) => {
                        if tx
                            .send(Ok(Bytes::copy_from_slice(&buffer[..read])))
                            .await
                            .is_err()
                        {
                            break Err(anyhow!("response body dropped"));
                        }
                    }
                    Err(error) => break Err(error.into()),
                }
            }
        }
    };
    if result.is_ok() && keep_alive {
        let stream = reader.into_inner();
        let mut idle = pool.lock();
        let conns = idle.entry(key.to_string()).or_default();
        if conns.len() < max_idle {
            conns.push(IdleConn {
                stream,
                idle_at: Instant::now(),
            });
        }
    } else if let Err(error) = result {
        let _ = tx.send(Err(error)).await;
    }
    let _ = idle_timeout;
    true
}

async fn read_chunked(
    reader: &mut BufReader<BoxStream>,
    tx: &mpsc::Sender<Result<Bytes>>,
) -> Result<()> {
    loop {
        let mut line = Vec::new();
        let read = reader.read_until(b'\n', &mut line).await?;
        if read == 0 {
            bail!("unexpected end of chunked body");
        }
        let text = String::from_utf8_lossy(&line);
        let size_text = text
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .trim_end_matches(['\r', '\n']);
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| anyhow!("invalid chunk size {size_text:?}"))?;
        if size == 0 {
            loop {
                let mut trailer = Vec::new();
                let read = reader.read_until(b'\n', &mut trailer).await?;
                if read == 0 || trailer == b"\r\n" || trailer == b"\n" {
                    break;
                }
            }
            return Ok(());
        }
        let mut remaining = size;
        let mut buffer = vec![0u8; 16 * 1024];
        while remaining > 0 {
            let want = remaining.min(buffer.len());
            let read = reader.read(&mut buffer[..want]).await?;
            if read == 0 {
                bail!("unexpected end of chunk");
            }
            remaining -= read;
            if tx
                .send(Ok(Bytes::copy_from_slice(&buffer[..read])))
                .await
                .is_err()
            {
                bail!("response body dropped");
            }
        }
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf).await?;
    }
}

async fn decode_body(
    encoding: String,
    mut reader: BufReader<StreamReader<ReceiverStream, Bytes>>,
    tx: &mpsc::Sender<Result<Bytes>>,
) -> Result<()> {
    use async_compression::tokio::bufread as compression;
    let mut buffer = vec![0u8; 16 * 1024];
    macro_rules! pump {
        ($decoder:expr) => {{
            let mut decoder = $decoder;
            loop {
                let read = decoder.read(&mut buffer).await?;
                if read == 0 {
                    break;
                }
                if tx
                    .send(Ok(Bytes::copy_from_slice(&buffer[..read])))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }};
    }
    match encoding.as_str() {
        "gzip" | "x-gzip" => pump!(compression::GzipDecoder::new(&mut reader)),
        "deflate" => pump!(compression::ZlibDecoder::new(&mut reader)),
        "br" => pump!(compression::BrotliDecoder::new(&mut reader)),
        "zstd" => pump!(compression::ZstdDecoder::new(&mut reader)),
        _ => {
            while reader.read(&mut buffer).await? > 0 {}
        }
    }
    Ok(())
}

fn connection_key(url: &Url) -> String {
    let port = url.port_or_known_default().unwrap_or(443);
    format!(
        "{}://{}:{}",
        url.scheme(),
        url.host_str().unwrap_or_default(),
        port
    )
}

fn proxy_address(proxy: &Url) -> String {
    let host = proxy.host_str().unwrap_or_default();
    let port = proxy.port_or_known_default().unwrap_or(match proxy.scheme() {
        "https" => 443,
        "socks5" | "socks5h" => 1080,
        _ => 80,
    });
    format!("{host}:{port}")
}

async fn http_connect(stream: &mut BoxStream, proxy: &Url, target: &str) -> Result<()> {
    let mut request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if !proxy.username().is_empty() || proxy.password().is_some() {
        use base64::Engine;
        let credentials = format!(
            "{}:{}",
            proxy.username(),
            proxy.password().unwrap_or_default()
        );
        request.push_str(&format!(
            "Proxy-Authorization: Basic {}\r\n",
            base64::engine::general_purpose::STANDARD.encode(credentials)
        ));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let mut reader = BufReader::new(stream);
    let mut line = Vec::new();
    reader.read_until(b'\n', &mut line).await?;
    let status = String::from_utf8_lossy(&line);
    let code = status
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| anyhow!("invalid proxy response"))?;
    loop {
        let mut header = Vec::new();
        let read = reader.read_until(b'\n', &mut header).await?;
        if read == 0 || header == b"\r\n" || header == b"\n" {
            break;
        }
    }
    if !(200..300).contains(&code) {
        bail!("proxy refused CONNECT: {code}");
    }
    Ok(())
}

async fn socks5_connect(stream: &mut BoxStream, proxy: &Url, target: &str) -> Result<()> {
    let (host, port) = split_host_port(target)?;
    let has_credentials = !proxy.username().is_empty() || proxy.password().is_some();
    let mut methods = vec![0u8];
    if has_credentials {
        methods.push(2);
    }
    let mut greeting = vec![5u8, methods.len() as u8];
    greeting.extend_from_slice(&methods);
    stream.write_all(&greeting).await?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    if reply[0] != 5 {
        bail!("unexpected SOCKS protocol version {}", reply[0]);
    }
    match reply[1] {
        0 => {}
        2 if has_credentials => {
            let name = proxy.username().as_bytes();
            let password = proxy.password().unwrap_or_default().as_bytes();
            if name.is_empty() || name.len() > 255 || password.len() > 255 {
                bail!("invalid username/password");
            }
            let mut auth = vec![1u8, name.len() as u8];
            auth.extend_from_slice(name);
            auth.push(password.len() as u8);
            auth.extend_from_slice(password);
            stream.write_all(&auth).await?;
            stream.read_exact(&mut reply).await?;
            if reply[1] != 0 {
                bail!("username/password authentication failed");
            }
        }
        _ => bail!("no acceptable SOCKS authentication methods"),
    }
    let mut request = vec![5u8, 1, 0];
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => match ip {
            std::net::IpAddr::V4(address) => {
                request.push(1);
                request.extend_from_slice(&address.octets());
            }
            std::net::IpAddr::V6(address) => {
                request.push(4);
                request.extend_from_slice(&address.octets());
            }
        },
        Err(_) => {
            if host.len() > 255 {
                bail!("FQDN too long");
            }
            request.push(3);
            request.push(host.len() as u8);
            request.extend_from_slice(host.as_bytes());
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != 5 {
        bail!("unexpected SOCKS protocol version {}", header[0]);
    }
    if header[1] != 0 {
        bail!("SOCKS CONNECT failed with code {}", header[1]);
    }
    let skip = match header[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            length[0] as usize
        }
        other => bail!("unknown SOCKS address type {other}"),
    };
    let mut discard = vec![0u8; skip + 2];
    stream.read_exact(&mut discard).await?;
    Ok(())
}

fn split_host_port(address: &str) -> Result<(String, u16)> {
    if let Some(rest) = address.strip_prefix('[') {
        let (host, rest) = rest
            .split_once(']')
            .ok_or_else(|| anyhow!("invalid address {address:?}"))?;
        let port = rest.trim_start_matches(':').parse::<u16>()?;
        return Ok((host.to_string(), port));
    }
    let (host, port) = address
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("invalid address {address:?}"))?;
    Ok((host.to_string(), port.parse::<u16>()?))
}

async fn read_response_head(
    reader: &mut BufReader<BoxStream>,
) -> Result<(StatusCode, HeaderMap)> {
    loop {
        let mut line = Vec::new();
        if reader.read_until(b'\n', &mut line).await? == 0 {
            bail!("empty response");
        }
        let status_line = String::from_utf8_lossy(&line).trim().to_string();
        let mut parts = status_line.splitn(3, ' ');
        let version = parts.next().unwrap_or_default();
        if !version.starts_with("HTTP/") {
            bail!("malformed HTTP response: {status_line:?}");
        }
        let code = parts
            .next()
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or_else(|| anyhow!("malformed status line {status_line:?}"))?;
        let status = StatusCode::from_u16(code)?;
        let mut headers = HeaderMap::new();
        loop {
            let mut header_line = Vec::new();
            let read = reader.read_until(b'\n', &mut header_line).await?;
            if read == 0 {
                bail!("unexpected end of response headers");
            }
            if header_line == b"\r\n" || header_line == b"\n" {
                break;
            }
            let text = String::from_utf8_lossy(&header_line);
            let text = text.trim_end_matches(['\r', '\n']);
            if let Some((name, value)) = text.split_once(':') {
                if let (Ok(name), Ok(value)) = (
                    HeaderName::from_bytes(name.trim().as_bytes()),
                    HeaderValue::from_str(value.trim()),
                ) {
                    headers.append(name, value);
                }
            }
        }
        if status.as_u16() < 200 && status != StatusCode::SWITCHING_PROTOCOLS {
            continue;
        }
        return Ok((status, headers));
    }
}

fn default_tls_config() -> Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = rustls::crypto::ring::default_provider();
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

fn regular_request_head(
    method: &str,
    url: &Url,
    headers: &HeaderMap,
    body_length: Option<usize>,
) -> Result<Vec<u8>> {
    let mut out = String::new();
    let path = if url.query().is_some() {
        format!("{}?{}", url.path(), url.query().unwrap_or_default())
    } else {
        url.path().to_string()
    };
    out.push_str(&format!("{method} {path} HTTP/1.1\r\n"));
    let host = host_header(url);
    out.push_str(&format!("Host: {host}\r\n"));
    let mut has_encoding = false;
    for (name, value) in headers {
        let lower = name.as_str().to_ascii_lowercase();
        if matches!(lower.as_str(), "host" | "connection" | "content-length" | "transfer-encoding") {
            continue;
        }
        if lower == "accept-encoding" {
            has_encoding = true;
        }
        out.push_str(&format!(
            "{name}: {}\r\n",
            value.to_str().unwrap_or_default()
        ));
    }
    out.push_str("Connection: keep-alive\r\n");
    if !headers.contains_key(ACCEPT_ENCODING) && !has_encoding {
        out.push_str("Accept-Encoding: gzip, deflate, br, zstd\r\n");
    }
    if let Some(length) = body_length {
        out.push_str(&format!("Content-Length: {length}\r\n"));
    }
    out.push_str("\r\n");
    Ok(out.into_bytes())
}

fn host_header(url: &Url) -> String {
    let host = url.host_str().unwrap_or_default();
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    }
}

/// Reads requests fully and closes the body, matching the Go transport.
pub async fn read_request_body(body: Option<Bytes>) -> Option<Bytes> {
    body
}

pub fn random_hex(size: usize) -> String {
    let mut buf = vec![0u8; size];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

#[allow(dead_code)]
fn _addr(_: ()) {}
