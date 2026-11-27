//! mihomo-compatible Brutal bandwidth negotiation.
//!
//! The client opens a bistream with the `MihomoBrutal` extension and sends the
//! download rate it wants (`rx`). The server sends to the client at
//! `min(client rx, server up)` and answers with its own receive rate, which
//! the client uses to cap its upload: `min(server rx, client up)`.
//!
//! Rates on the wire are bytes per second (Hysteria2 semantics). Configuration
//! and the Brutal controller use bits per second.

use std::time::Duration;

use tracing::{debug, info};

use crate::{
    error::{SError, SResult},
    msgs::{
        SDecode, SEncode,
        squic::{BrutalNegotiation, SQExtError, SQExtOpcode, SQReq},
    },
    quic::{BrutalRates, QuicConnection},
};

use super::SQConn;

/// Same timeout as mihomo's client.
pub(crate) const BRUTAL_NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(10);

fn bits_to_wire(bps: u64) -> u64 {
    bps / 8
}

fn wire_to_bits(rx: u64) -> u64 {
    rx.saturating_mul(8)
}

/// Server send rate, in bits per second, for a client asking for `client_rx`
/// bytes per second. `None` keeps the configured rate.
pub(crate) fn server_send_rate(up: u64, client_rx: u64) -> Option<u64> {
    (client_rx > 0).then(|| wire_to_bits(client_rx).min(up))
}

/// Client send rate, in bits per second, after the server's response.
/// `None` keeps the configured rate.
pub(crate) fn client_send_rate(up: u64, response: &BrutalNegotiation) -> Option<u64> {
    (!response.rx_auto() && response.rx > 0).then(|| wire_to_bits(response.rx).min(up))
}

/// Response the server sends for its configured rates.
pub(crate) fn server_response(rates: &BrutalRates) -> BrutalNegotiation {
    BrutalNegotiation {
        flags: 0,
        rx: rates.down.map(bits_to_wire).unwrap_or(0),
    }
}

/// Handles a client's negotiation request on the server.
pub(crate) async fn handle_negotiation<C, W>(
    conn: &C,
    request: BrutalNegotiation,
    send: &mut W,
) -> SResult<()>
where
    C: QuicConnection,
    W: tokio::io::AsyncWrite + Unpin + Send,
{
    let Some(rates) = conn.brutal_rates() else {
        debug!(
            event = "recovery:brutal_negotiation_unavailable",
            "brutal negotiation requested but brutal congestion control is not configured"
        );
        Err::<(), _>(SQExtError::NotAvailable).encode(send).await?;
        return Ok(());
    };
    if let Some(rate) = server_send_rate(rates.up, request.rx) {
        conn.set_brutal_send_rate(rate);
        info!(
            event = "recovery:brutal_negotiated",
            client_rx_bps = wire_to_bits(request.rx),
            send_bps = rate,
            "brutal send rate negotiated with client"
        );
    } else {
        debug!(
            event = "recovery:brutal_negotiated",
            send_bps = rates.up,
            "client sent no receive rate, keeping configured brutal send rate"
        );
    }
    server_response(&rates).encode(send).await?;
    Ok(())
}

/// Negotiates Brutal rates with the server. Returns the applied send rate in
/// bits per second, or `None` when the configured rate is kept.
///
/// Does nothing when the connection does not use Brutal or no `down` rate is
/// configured, so servers without the extension never see the request.
pub async fn negotiate<C: QuicConnection>(sq_conn: &SQConn<C>) -> SResult<Option<u64>> {
    let Some(rates) = sq_conn.brutal_rates() else {
        return Ok(None);
    };
    let Some(down) = rates.down else {
        return Ok(None);
    };
    let response = tokio::time::timeout(BRUTAL_NEGOTIATION_TIMEOUT, async {
        let (mut send, mut recv, _id) = sq_conn.open_bi().await?;
        SQReq::SQExtension(SQExtOpcode::MihomoBrutal(BrutalNegotiation {
            flags: 0,
            rx: bits_to_wire(down),
        }))
        .encode(&mut send)
        .await?;
        BrutalNegotiation::decode(&mut recv).await
    })
    .await
    .map_err(|_| SError::from(std::io::Error::from(std::io::ErrorKind::TimedOut)))??;

    let rate = client_send_rate(rates.up, &response);
    if let Some(rate) = rate {
        sq_conn.set_brutal_send_rate(rate);
    }
    info!(
        event = "recovery:brutal_negotiated",
        server_rx_bps = wire_to_bits(response.rx),
        rx_auto = response.rx_auto(),
        send_bps = rate.unwrap_or(rates.up),
        "brutal send rate negotiated with server"
    );
    Ok(rate)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MBIT: u64 = 1_000_000;

    #[test]
    fn server_caps_client_request_with_its_upload() {
        // Client asks for 200 Mbit/s, server can send 100 Mbit/s.
        assert_eq!(
            server_send_rate(100 * MBIT, 200 * MBIT / 8),
            Some(100 * MBIT)
        );
        // Client asks for less than the server can send.
        assert_eq!(server_send_rate(100 * MBIT, 50 * MBIT / 8), Some(50 * MBIT));
    }

    #[test]
    fn server_keeps_configured_rate_without_client_rx() {
        assert_eq!(server_send_rate(100 * MBIT, 0), None);
    }

    #[test]
    fn client_caps_server_rx_with_its_upload() {
        let response = BrutalNegotiation {
            flags: 0,
            rx: 20 * MBIT / 8,
        };
        assert_eq!(client_send_rate(100 * MBIT, &response), Some(20 * MBIT));
        assert_eq!(client_send_rate(10 * MBIT, &response), Some(10 * MBIT));
    }

    #[test]
    fn client_keeps_configured_rate_on_auto_or_unknown_server_rx() {
        let unknown = BrutalNegotiation { flags: 0, rx: 0 };
        assert_eq!(client_send_rate(100 * MBIT, &unknown), None);
        let auto = BrutalNegotiation {
            flags: crate::msgs::squic::BRUTAL_NEGOTIATION_FLAG_RX_AUTO,
            rx: 20 * MBIT / 8,
        };
        assert_eq!(client_send_rate(100 * MBIT, &auto), None);
    }

    #[test]
    fn server_reports_down_in_bytes_per_second() {
        let rates = BrutalRates {
            up: 100 * MBIT,
            down: Some(80 * MBIT),
        };
        assert_eq!(server_response(&rates).rx, 10 * MBIT);
        let rates = BrutalRates {
            up: 100 * MBIT,
            down: None,
        };
        assert_eq!(server_response(&rates).rx, 0);
    }

    #[test]
    fn huge_wire_rate_saturates() {
        assert_eq!(server_send_rate(u64::MAX, u64::MAX), Some(u64::MAX));
    }
}
