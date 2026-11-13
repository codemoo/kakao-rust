//! Single-owner socket transport. TLS for booking, V2SL for discovered servers.
//! Never logs payloads, endpoints, credentials or raw I/O/crypto errors.
use super::{
    codec::{Decoder, Packet, ProtocolError},
    crypto::SecureLayer,
};
use std::{collections::VecDeque, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tokio_rustls::{
    rustls::{self, pki_types::ServerName},
    TlsConnector,
};
use zeroize::Zeroizing;

const TIMEOUT: Duration = Duration::from_secs(10);
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    #[error("LOCO transport failure")]
    Io,
    #[error("LOCO operation timed out")]
    Timeout,
    #[error("LOCO TLS verification failed")]
    Tls,
    #[error("LOCO remote stream ended")]
    Closed,
    #[error("LOCO unexpected response correlation")]
    Correlation,
    #[error("LOCO unsolicited packet backlog exceeded")]
    Backlog,
    #[error("LOCO connection unusable after interrupted operation")]
    Poisoned,
    #[error("LOCO protocol: {0}")]
    Protocol(#[from] ProtocolError),
}
pub type Result<T> = std::result::Result<T, TransportError>;
trait Socket: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Socket for T {}
pub struct Connection {
    socket: Box<dyn Socket>,
    secure: Option<SecureLayer>,
    handshake_sent: bool,
    decoder: Decoder,
    unsolicited: VecDeque<Packet>,
    unsolicited_bytes: usize,
    poisoned: bool,
}
impl Connection {
    #[cfg(test)]
    pub(crate) fn test_socket(socket: tokio::io::DuplexStream) -> Self {
        Self::new(Box::new(socket), None)
    }
    pub async fn booking() -> Result<Self> {
        let host = "booking-loco.kakao.com";
        let socket = timeout(TIMEOUT, TcpStream::connect((host, 443)))
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|_| TransportError::Io)?;
        socket.set_nodelay(true).map_err(|_| TransportError::Io)?;
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = ServerName::try_from(host).map_err(|_| TransportError::Tls)?;
        let tls = timeout(
            TIMEOUT,
            TlsConnector::from(Arc::new(config)).connect(name, socket),
        )
        .await
        .map_err(|_| TransportError::Timeout)?
        .map_err(|_| TransportError::Tls)?;
        Ok(Self::new(Box::new(tls), None))
    }
    /// Only call with an endpoint obtained from the preceding verified server response.
    pub async fn discovered(host: &str, port: u16) -> Result<Self> {
        let socket = timeout(TIMEOUT, TcpStream::connect((host, port)))
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|_| TransportError::Io)?;
        socket.set_nodelay(true).map_err(|_| TransportError::Io)?;
        Ok(Self::new(Box::new(socket), Some(SecureLayer::random())))
    }
    fn new(socket: Box<dyn Socket>, secure: Option<SecureLayer>) -> Self {
        Self {
            socket,
            secure,
            handshake_sent: false,
            decoder: Decoder::default(),
            unsolicited: VecDeque::new(),
            unsolicited_bytes: 0,
            poisoned: false,
        }
    }
    pub async fn send(&mut self, packet: &Packet) -> Result<()> {
        if self.poisoned {
            return Err(TransportError::Poisoned);
        }
        // Set before the first await; dropping this future leaves the socket poisoned.
        self.poisoned = true;
        let result = timeout(TIMEOUT, self.send_inner(packet))
            .await
            .map_err(|_| TransportError::Timeout)?;
        if result.is_ok() {
            self.poisoned = false;
        }
        result
    }
    async fn send_inner(&mut self, packet: &Packet) -> Result<()> {
        let bytes = packet.encode()?;
        if let Some(secure) = &self.secure {
            if !self.handshake_sent {
                let handshake = secure.handshake()?;
                self.socket
                    .write_all(&handshake)
                    .await
                    .map_err(|_| TransportError::Io)?;
                self.handshake_sent = true;
            }
            // Write complete 8192-byte segments; secure records are
            // independent of packet boundaries and receiver reassembles the stream.
            for chunk in bytes.chunks(8192) {
                self.socket
                    .write_all(&secure.encrypt(chunk)?)
                    .await
                    .map_err(|_| TransportError::Io)?;
            }
        } else {
            self.socket
                .write_all(&bytes)
                .await
                .map_err(|_| TransportError::Io)?;
        }
        self.socket.flush().await.map_err(|_| TransportError::Io)
    }
    pub async fn receive(&mut self) -> Result<Packet> {
        if self.poisoned {
            return Err(TransportError::Poisoned);
        }
        self.poisoned = true;
        let result = self.receive_inner().await;
        if result.is_ok() {
            self.poisoned = false;
        }
        result
    }
    async fn receive_inner(&mut self) -> Result<Packet> {
        loop {
            if let Some(packet) = self.decoder.next_packet()? {
                return Ok(packet);
            }
            self.read_record().await?;
        }
    }
    async fn read_record(&mut self) -> Result<()> {
        if let Some(secure) = &self.secure {
            let mut prefix = [0; 4];
            self.socket
                .read_exact(&mut prefix)
                .await
                .map_err(|_| TransportError::Closed)?;
            let length = SecureLayer::record_length(prefix)?;
            let mut encrypted = vec![0; length];
            self.socket
                .read_exact(&mut encrypted)
                .await
                .map_err(|_| TransportError::Closed)?;
            let bytes = secure.decrypt(&encrypted)?;
            self.decoder.feed(&bytes)?;
        } else {
            let mut bytes = Zeroizing::new([0; 8192]);
            let n = self
                .socket
                .read(&mut *bytes)
                .await
                .map_err(|_| TransportError::Io)?;
            if n == 0 {
                return Err(TransportError::Closed);
            }
            self.decoder.feed(&bytes[..n])?;
        }
        Ok(())
    }
    /// DOWN switches from BSON framing to exactly `s` raw plaintext bytes.
    /// This isolated connection must never return to the normal packet reader.
    pub(crate) async fn raw_chunk(&mut self, remaining: u64) -> Result<Vec<u8>> {
        if self.poisoned {
            return Err(TransportError::Poisoned);
        }
        self.poisoned = true;
        let result = timeout(TIMEOUT, async {
            loop {
                let chunk = self.decoder.take_raw(remaining.min(65536) as usize);
                if !chunk.is_empty() || remaining == 0 {
                    return Ok(chunk);
                }
                self.read_record().await?;
            }
        })
        .await
        .map_err(|_| TransportError::Timeout)?;
        if result.is_ok() {
            self.poisoned = false;
        }
        result
    }
    pub async fn exchange(&mut self, request: &Packet) -> Result<Packet> {
        self.send(request).await?;
        timeout(TIMEOUT, async {
            loop {
                let response = self.receive().await?;
                if response.header.packet_id == request.header.packet_id {
                    if response.header.command != request.header.command {
                        self.poisoned = true;
                        return Err(TransportError::Correlation);
                    }
                    return Ok(response);
                }
                let size = response.header.body_len + super::codec::HEADER_LEN;
                if self.unsolicited.len() >= 128 || size > 8 * 1024 * 1024 - self.unsolicited_bytes
                {
                    self.poisoned = true;
                    return Err(TransportError::Backlog);
                }
                self.unsolicited_bytes += size;
                self.unsolicited.push_back(response);
            }
        })
        .await
        .map_err(|_| TransportError::Timeout)?
    }
    pub fn pop_unsolicited(&mut self) -> Option<Packet> {
        let packet = self.unsolicited.pop_front()?;
        self.unsolicited_bytes -= packet.header.body_len + super::codec::HEADER_LEN;
        Some(packet)
    }
}
/// A dedicated reader owns framing buffers continuously. Timer cancellation only
/// drops a channel receive, never a partially consumed TLS/V2SL record.
pub struct LiveConnection {
    writer: Connection,
    incoming: tokio::sync::mpsc::Receiver<Result<Packet>>,
    reader: tokio::task::JoinHandle<()>,
}
impl Connection {
    pub fn into_live(self) -> Result<LiveConnection> {
        self.into_live_guarded(None)
    }
    pub(crate) fn into_live_guarded(
        self,
        lease: Option<std::sync::Arc<crate::runtime::RuntimeLease>>,
    ) -> Result<LiveConnection> {
        if self.poisoned {
            return Err(TransportError::Poisoned);
        }
        let (read, write) = tokio::io::split(self.socket);
        let mut receiver = Connection::new(
            Box::new(ReadOnly(read)),
            self.secure.as_ref().map(SecureLayer::copy_for_receive),
        );
        receiver.decoder = self.decoder;
        receiver.unsolicited = self.unsolicited;
        receiver.unsolicited_bytes = self.unsolicited_bytes;
        let mut writer = Connection::new(Box::new(WriteOnly(write)), self.secure);
        writer.handshake_sent = self.handshake_sent;
        // One queued + one in-flight packet; bounded by MAX_BODY each.
        let (tx, incoming) = tokio::sync::mpsc::channel(1);
        let reader = tokio::spawn(async move {
            let _lease = lease;
            loop {
                let packet = match receiver.pop_unsolicited() {
                    Some(packet) => Ok(packet),
                    None => receiver.receive().await,
                };
                let failed = packet.is_err();
                if tx.send(packet).await.is_err() || failed {
                    break;
                }
            }
        });
        Ok(LiveConnection {
            writer,
            incoming,
            reader,
        })
    }
}
impl LiveConnection {
    pub async fn send(&mut self, packet: &Packet) -> Result<()> {
        self.writer.send(packet).await
    }
    pub async fn receive(&mut self) -> Result<Packet> {
        self.incoming.recv().await.ok_or(TransportError::Closed)?
    }
    pub async fn close(mut self) {
        self.reader.abort();
        let _ = (&mut self.reader).await;
    }
}
impl Drop for LiveConnection {
    fn drop(&mut self) {
        self.reader.abort();
    }
}
struct ReadOnly(tokio::io::ReadHalf<Box<dyn Socket>>);
struct WriteOnly(tokio::io::WriteHalf<Box<dyn Socket>>);
impl AsyncRead for ReadOnly {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}
impl AsyncWrite for ReadOnly {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Ready(Err(std::io::ErrorKind::Unsupported.into()))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Err(std::io::ErrorKind::Unsupported.into()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Err(std::io::ErrorKind::Unsupported.into()))
    }
}
impl AsyncRead for WriteOnly {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Err(std::io::ErrorKind::Unsupported.into()))
    }
}
impl AsyncWrite for WriteOnly {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, bytes)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bson::doc;
    #[tokio::test]
    async fn trailer_preserves_raw_tail_across_secure_records_and_rejects_short_eof() {
        let secure = SecureLayer::random();
        let (client, mut server) = tokio::io::duplex(4096);
        let mut client = Connection::new(Box::new(client), Some(secure.copy_for_receive()));
        let mut first = Packet::request(1, "DOWN", doc! {"s":10})
            .unwrap()
            .encode()
            .unwrap()
            .to_vec();
        first.extend_from_slice(b"abc");
        server
            .write_all(&secure.encrypt(&first).unwrap())
            .await
            .unwrap();
        server
            .write_all(&secure.encrypt(b"defghij").unwrap())
            .await
            .unwrap();
        assert_eq!(
            client.receive().await.unwrap().body.get_i32("s").unwrap(),
            10
        );
        assert_eq!(client.raw_chunk(10).await.unwrap(), b"abc");
        assert_eq!(client.raw_chunk(7).await.unwrap(), b"defghij");
        drop(server);
        assert!(client.raw_chunk(1).await.is_err());
        assert!(matches!(
            client.raw_chunk(1).await,
            Err(TransportError::Poisoned)
        ));
    }
    #[tokio::test]
    async fn heartbeat_during_partial_receive_preserves_framing() {
        let (client, mut server) = tokio::io::duplex(256);
        let bytes = Packet::request(0, "MSG", doc! {"synthetic":true})
            .unwrap()
            .encode()
            .unwrap();
        server.write_all(&bytes[..3]).await.unwrap();
        let mut live = Connection::new(Box::new(client), None).into_live().unwrap();
        assert!(timeout(Duration::from_millis(20), live.receive())
            .await
            .is_err());
        live.send(&Packet::request(1000, "PING", doc! {}).unwrap())
            .await
            .unwrap();
        let mut ping = [0; 27];
        server.read_exact(&mut ping).await.unwrap();
        assert_eq!(&ping[6..10], b"PING");
        server.write_all(&bytes[3..]).await.unwrap();
        assert_eq!(live.receive().await.unwrap().header.command, "MSG");
        live.close().await;
    }
    #[tokio::test]
    async fn split_stream_and_unsolicited_packets_are_not_lost() {
        let (client, mut server) = tokio::io::duplex(256);
        let task = tokio::spawn(async move {
            let mut request = [0; 27];
            server.read_exact(&mut request).await.unwrap();
            let push = Packet::request(0, "MSG", doc! {"synthetic":true})
                .unwrap()
                .encode()
                .unwrap();
            let reply = Packet::request(1, "PING", doc! {})
                .unwrap()
                .encode()
                .unwrap();
            for byte in push.iter().chain(reply.iter()) {
                server.write_all(&[*byte]).await.unwrap();
            }
        });
        let mut client = Connection::new(Box::new(client), None);
        let response = client
            .exchange(&Packet::request(1, "PING", doc! {}).unwrap())
            .await
            .unwrap();
        assert_eq!(response.header.command, "PING");
        assert_eq!(client.pop_unsolicited().unwrap().header.command, "MSG");
        task.await.unwrap();
    }
    #[tokio::test]
    async fn correlation_mismatch_is_not_success() {
        let (client, mut server) = tokio::io::duplex(256);
        let task = tokio::spawn(async move {
            let mut request = [0; 27];
            server.read_exact(&mut request).await.unwrap();
            let bytes = Packet::request(1, "LOGINLIST", doc! {})
                .unwrap()
                .encode()
                .unwrap();
            server.write_all(&bytes).await.unwrap();
        });
        let mut client = Connection::new(Box::new(client), None);
        assert_eq!(
            client
                .exchange(&Packet::request(1, "PING", doc! {}).unwrap())
                .await
                .err()
                .unwrap(),
            TransportError::Correlation
        );
        task.await.unwrap();
    }
    #[tokio::test]
    async fn cancelled_partial_secure_read_cannot_reuse_connection() {
        for bytes in [vec![44, 0], vec![44, 0, 0, 0, 1, 2, 3]] {
            let (client, mut server) = tokio::io::duplex(256);
            server.write_all(&bytes).await.unwrap();
            let mut client = Connection::new(Box::new(client), Some(SecureLayer::random()));
            assert!(timeout(Duration::from_millis(20), client.receive())
                .await
                .is_err());
            assert_eq!(
                client.receive().await.err().unwrap(),
                TransportError::Poisoned
            );
            assert_eq!(
                client
                    .send(&Packet::request(1, "PING", doc! {}).unwrap())
                    .await
                    .err()
                    .unwrap(),
                TransportError::Poisoned
            );
        }
    }
    #[tokio::test]
    async fn cancelled_partial_secure_send_cannot_reuse_connection() {
        let (client, _server) = tokio::io::duplex(4);
        let mut client = Connection::new(Box::new(client), Some(SecureLayer::random()));
        assert!(timeout(
            Duration::from_millis(20),
            client.send(&Packet::request(1, "PING", doc! {}).unwrap())
        )
        .await
        .is_err());
        assert_eq!(
            client
                .send(&Packet::request(2, "PING", doc! {}).unwrap())
                .await
                .err()
                .unwrap(),
            TransportError::Poisoned
        );
    }
}
