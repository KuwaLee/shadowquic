use std::sync::Arc;

use crate::UserName;
use crate::error::{SError, SResult};

use super::socks5::SocksAddr;
use super::{SDecode, SEncode};
use crate::config::AuthUser;
use shadowquic_macros::{SDecode, SEncode};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub static SUNNY_QUIC_AUTH_LEN: usize = 64;
pub(crate) type SunnyCredential = Arc<[u8; SUNNY_QUIC_AUTH_LEN]>;

pub const SQ_REQ_CONNECT: u8 = 0x1;
pub const SQ_REQ_BIND: u8 = 0x2;
pub const SQ_REQ_ASSOCIATE_OVER_DATAGRAM: u8 = 0x3;
pub const SQ_REQ_ASSOCIATE_OVER_STREAM: u8 = 0x4;
pub const SQ_REQ_AUTHENTICATE: u8 = 0x5;
pub const SQ_REQ_EXTENSION: u8 = 0xFF;

#[derive(PartialEq)]
#[repr(u8)]
#[derive(SEncode, SDecode)]
pub enum SQReq {
    SQConnect(SocksAddr) = SQ_REQ_CONNECT,
    SQBind(SocksAddr) = SQ_REQ_BIND,
    SQAssociatOverDatagram(SocksAddr) = SQ_REQ_ASSOCIATE_OVER_DATAGRAM,
    SQAssociatOverStream(SocksAddr) = SQ_REQ_ASSOCIATE_OVER_STREAM,
    SQAuthenticate(SunnyCredential) = SQ_REQ_AUTHENTICATE,
    SQExtension(SQExtOpcode) = SQ_REQ_EXTENSION,
}

impl SQReq {
    pub async fn decode_tag<T: AsyncRead + Unpin + Send>(s: &mut T) -> SResult<u8> {
        u8::decode(s).await
    }
    pub async fn decode_with_tag<T: AsyncRead + Unpin + Send>(tag: u8, s: &mut T) -> SResult<Self> {
        let prefix = [tag];
        let mut s = prefix.chain(s);
        Self::decode(&mut s).await
    }
}

#[derive(PartialEq)]
#[repr(u64)]
#[derive(SEncode, SDecode)]
/// SQ Extention Opcode
pub enum SQExtOpcode {
    /// Connection related opcode
    Conn(ExtOpcodeConn) = 0x1,
    /// User related opcode
    User(ExtOpcodeUser) = 0x2,
    /// mihomo private Brutal bandwidth negotiation: ASCII "mihomo" + id 1.
    MihomoBrutal(BrutalNegotiation) = EXT_OPCODE_MIHOMO_BRUTAL,
}

/// Opcode of the mihomo private Brutal negotiation extension.
pub const EXT_OPCODE_MIHOMO_BRUTAL: u64 = 0x6d69686f6d6f0001;

const BRUTAL_NEGOTIATION_VERSION: u8 = 1;
const BRUTAL_NEGOTIATION_MIN_PAYLOAD_LEN: u16 = 8;
const BRUTAL_NEGOTIATION_MAX_PAYLOAD_LEN: u16 = 64;
/// Response flag: the server did not get a client rate and uses automatic
/// congestion control.
pub const BRUTAL_NEGOTIATION_FLAG_RX_AUTO: u8 = 1 << 0;

/// Frame of the mihomo Brutal negotiation, used for both the request body and
/// the response:
///
/// `version(1) | flags(1) | payload length(2) | payload`
///
/// Version 1 defines the first 8 payload bytes as `rx`, the desired receive
/// bandwidth in bytes per second (0 = unknown/auto). Unknown flags and trailing
/// payload bytes are ignored so the frame can be extended.
#[derive(PartialEq, Debug, Clone, Copy, Default)]
pub struct BrutalNegotiation {
    pub flags: u8,
    /// Receive bandwidth in bytes per second, 0 for unknown/auto.
    pub rx: u64,
}

impl BrutalNegotiation {
    pub fn rx_auto(&self) -> bool {
        self.flags & BRUTAL_NEGOTIATION_FLAG_RX_AUTO != 0
    }
}

#[async_trait::async_trait]
impl SEncode for BrutalNegotiation {
    async fn encode<W: AsyncWrite + Unpin + Send>(&self, s: &mut W) -> SResult<()> {
        let mut buf = [0u8; 12];
        buf[0] = BRUTAL_NEGOTIATION_VERSION;
        buf[1] = self.flags;
        buf[2..4].copy_from_slice(&BRUTAL_NEGOTIATION_MIN_PAYLOAD_LEN.to_be_bytes());
        buf[4..12].copy_from_slice(&self.rx.to_be_bytes());
        s.write_all(&buf).await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl SDecode for BrutalNegotiation {
    async fn decode<R: AsyncRead + Unpin + Send>(s: &mut R) -> SResult<Self> {
        let mut header = [0u8; 4];
        s.read_exact(&mut header).await?;
        if header[0] != BRUTAL_NEGOTIATION_VERSION {
            return Err(SError::ProtocolViolation);
        }
        let payload_len = u16::from_be_bytes([header[2], header[3]]);
        if !(BRUTAL_NEGOTIATION_MIN_PAYLOAD_LEN..=BRUTAL_NEGOTIATION_MAX_PAYLOAD_LEN)
            .contains(&payload_len)
        {
            return Err(SError::ProtocolViolation);
        }
        let mut payload = [0u8; BRUTAL_NEGOTIATION_MAX_PAYLOAD_LEN as usize];
        let payload = &mut payload[..payload_len as usize];
        s.read_exact(payload).await?;
        let mut rx = [0u8; 8];
        rx.copy_from_slice(&payload[..8]);
        Ok(Self {
            flags: header[1],
            rx: u64::from_be_bytes(rx),
        })
    }
}
#[derive(PartialEq)]
#[repr(u8)]
#[derive(SEncode, SDecode)]
pub enum ExtOpcodeConn {
    /// Get connection stats
    GetConnStats = 0x0,
}
#[derive(PartialEq, SEncode, SDecode, Clone)]
#[cfg_attr(feature = "restful-api", derive(serde::Serialize))]
#[size_tag] // size tag allow future compatibility by prefixing a size field before the content, so that decoder can skip unknown opcode content based on the size field.
pub struct ConnStats {
    pub lost_packets: u64,
    pub sent_packets: u64,
    /// In unit of milliseconds
    pub rtt: f64,
    pub current_mtu: u16,
}

#[derive(PartialEq)]
#[repr(u8)]
#[derive(SEncode, SDecode)]
pub enum ExtOpcodeUser {
    AddUser(AuthUser) = 0x0,
    RemoveUser(UserName) = 0x1,
    ListUsers = 0x2,
    GetUserStats(UserName) = 0x3,
    KillUserConn(UserName) = 0x4,
    GetAllStats = 0x5,
    ClearUserStats(UserName) = 0x6,
    ClearAllStats = 0x7,
}
#[derive(PartialEq)]
#[repr(u8)]
#[derive(SEncode, SDecode, Debug)]
pub enum SQExtError {
    NotAvailable = 0x0,
    PermissionDenied = 0x1,
    NotFound = 0x2,
    Other(String) = 0xFF,
}

#[derive(PartialEq, SEncode, SDecode, Default)]
#[size_tag]
pub struct UserStats {
    pub tcp_sent: u64,
    pub tcp_recv: u64,
    pub udp_sent: u64,
    pub udp_recv: u64,
    pub tcp_conns: u64,
    pub udp_conns: u64,
    /// Number of online connections, equal to devices connected.
    pub conn_num: u32,
    /// User these stats belong to. Added in v0.3.11
    pub username: UserName,
}

#[derive(SEncode, SDecode)]
pub struct SQUdpControlHeader {
    pub dst: SocksAddr,
    pub id: u16, // id is one to one coresponance a udpsocket and proxy dst
}

#[derive(SEncode, SDecode)]
pub struct SQPacketStreamHeader {
    pub id: u16, // id is one to one coresponance a udpsocket and proxy dst
    pub len: u16,
}

#[derive(SEncode, SDecode, Clone)]
pub struct SQPacketDatagramHeader {
    pub id: u16, // id is one to one coresponance a udpsocket and proxy dst
}

#[tokio::test]
async fn test_mihomo_brutal_request_wire_format() {
    let req = SQReq::SQExtension(SQExtOpcode::MihomoBrutal(BrutalNegotiation {
        flags: 0,
        rx: 12_500_000,
    }));
    let mut buf = Vec::new();
    req.encode(&mut buf).await.unwrap();
    let mut expected = vec![0xff];
    expected.extend_from_slice(&0x6d69686f6d6f0001u64.to_be_bytes());
    expected.extend_from_slice(&[1, 0, 0, 8]);
    expected.extend_from_slice(&12_500_000u64.to_be_bytes());
    assert_eq!(buf, expected);

    let mut cursor = std::io::Cursor::new(buf);
    let decoded = SQReq::decode(&mut cursor).await.unwrap();
    assert!(decoded == req);
}

#[tokio::test]
async fn test_brutal_negotiation_ignores_trailing_payload_and_flags() {
    let mut buf = vec![1, 0x81, 0, 10];
    buf.extend_from_slice(&42u64.to_be_bytes());
    buf.extend_from_slice(&[0xaa, 0xbb]);
    let decoded = BrutalNegotiation::decode(&mut std::io::Cursor::new(buf))
        .await
        .unwrap();
    assert_eq!(decoded.rx, 42);
    assert!(decoded.rx_auto());
}

#[tokio::test]
async fn test_brutal_negotiation_rejects_bad_frames() {
    // Unsupported version.
    let mut buf = vec![2, 0, 0, 8];
    buf.extend_from_slice(&0u64.to_be_bytes());
    assert!(
        BrutalNegotiation::decode(&mut std::io::Cursor::new(buf))
            .await
            .is_err()
    );
    // Payload too short.
    let buf = vec![1, 0, 0, 4, 0, 0, 0, 0];
    assert!(
        BrutalNegotiation::decode(&mut std::io::Cursor::new(buf))
            .await
            .is_err()
    );
    // A NotAvailable extension error is not a valid response.
    let mut buf = Vec::new();
    Err::<(), SQExtError>(SQExtError::NotAvailable)
        .encode(&mut buf)
        .await
        .unwrap();
    assert_eq!(buf, [0x01, 0x00]);
    assert!(
        BrutalNegotiation::decode(&mut std::io::Cursor::new(buf))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn test_encode_req() {
    let req = SQReq::SQAuthenticate(Arc::new([1u8; SUNNY_QUIC_AUTH_LEN]));
    let buf = vec![0u8; 1 + SUNNY_QUIC_AUTH_LEN];
    let mut cursor = std::io::Cursor::new(buf);
    req.encode(&mut cursor).await.unwrap();
    assert_eq!(cursor.into_inner()[0], 0x5);
}

#[tokio::test]
async fn test_macro_expand_req() {
    const TEST_CONST: u8 = 89;
    #[repr(u8)]
    #[derive(SDecode, SEncode, PartialEq)]
    #[allow(dead_code)]
    pub enum Cmd {
        Connect,
        Bind = 0x8,
        AssociatOverDatagram,
        AssociatOverStream = TEST_CONST,
        Authenticate,
    }
}
