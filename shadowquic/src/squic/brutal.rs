//! mihomo-compatible Brutal bandwidth negotiation, with Hysteria2 semantics.
//!
//! Each side decides how it sends; negotiation only exchanges receive rates.
//! The client opens a bistream with the `MihomoBrutal` extension and sends
//! the download rate it wants (`rx`, 0 = unknown).
//!
//! Server:
//! - `ignore-client-bandwidth`: keep the base congestion control and answer
//!   `RX_AUTO`.
//! - Otherwise send with Brutal at the client's `rx`, capped by the server's
//!   `bandwidth` when set. Without a client `rx`, use the base congestion
//!   control. Answer with the server's `down` (0 = no limit).
//!
//! Client:
//! - `RX_AUTO`: use the base congestion control.
//! - Otherwise send with Brutal at `min(server rx, bandwidth)`, where a server
//!   `rx` of 0 means no limit. Without `bandwidth`, use the base congestion
//!   control.
//!
//! Rates on the wire are bytes per second. Configuration and the Brutal
//! controller use bits per second.

use std::time::Duration;

use tracing::{debug, info};

use crate::{
    error::{SError, SResult},
    msgs::{
        SDecode, SEncode,
        squic::{
            BRUTAL_NEGOTIATION_FLAG_RX_AUTO, BrutalNegotiation, SQExtError, SQExtOpcode, SQReq,
        },
    },
    quic::{BrutalRates, BrutalSendMode, QuicConnection},
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

fn brutal_or_base(bps: u64) -> BrutalSendMode {
    if bps > 0 {
        BrutalSendMode::Brutal(bps)
    } else {
        BrutalSendMode::Base
    }
}

/// Server decision for a client asking for `client_rx` bytes per second:
/// the server's send mode and its response.
pub(crate) fn server_decision(
    rates: &BrutalRates,
    client_rx: u64,
    ignore_client_bandwidth: bool,
) -> (BrutalSendMode, BrutalNegotiation) {
    let rx = rates.down.map(bits_to_wire).unwrap_or(0);
    if ignore_client_bandwidth {
        let response = BrutalNegotiation {
            flags: BRUTAL_NEGOTIATION_FLAG_RX_AUTO,
            rx,
        };
        return (BrutalSendMode::Base, response);
    }
    let mut tx = wire_to_bits(client_rx);
    if let Some(up) = rates.up {
        tx = tx.min(up);
    }
    (brutal_or_base(tx), BrutalNegotiation { flags: 0, rx })
}

/// Client send mode after the server's response.
pub(crate) fn client_decision(rates: &BrutalRates, response: &BrutalNegotiation) -> BrutalSendMode {
    if response.rx_auto() {
        return BrutalSendMode::Base;
    }
    let up = rates.up.unwrap_or(0);
    let mut tx = wire_to_bits(response.rx);
    if tx == 0 || tx > up {
        tx = up;
    }
    brutal_or_base(tx)
}

/// Handles a client's negotiation request on the server.
pub(crate) async fn handle_negotiation<C, W>(
    conn: &C,
    request: BrutalNegotiation,
    ignore_client_bandwidth: bool,
    send: &mut W,
) -> SResult<()>
where
    C: QuicConnection,
    W: tokio::io::AsyncWrite + Unpin + Send,
{
    let Some(rates) = conn.brutal_rates() else {
        debug!(
            event = "recovery:brutal_negotiation_unavailable",
            "brutal negotiation is not supported on this connection"
        );
        Err::<(), _>(SQExtError::NotAvailable).encode(send).await?;
        return Ok(());
    };
    let (mode, response) = server_decision(&rates, request.rx, ignore_client_bandwidth);
    conn.set_brutal_send_mode(mode);
    info!(
        event = "recovery:brutal_negotiated",
        client_rx_bps = wire_to_bits(request.rx),
        ignore_client_bandwidth,
        ?mode,
        "brutal negotiated with client"
    );
    response.encode(send).await?;
    Ok(())
}

/// Negotiates Brutal with the server and applies the resulting send mode.
///
/// Returns `None` without contacting the server when Brutal is not
/// configured. On failure the connection keeps its configured behavior.
pub async fn negotiate<C: QuicConnection>(sq_conn: &SQConn<C>) -> SResult<Option<BrutalSendMode>> {
    let Some(rates) = sq_conn.brutal_rates() else {
        return Ok(None);
    };
    if rates.up.is_none() && rates.down.is_none() {
        return Ok(None);
    }
    let response = tokio::time::timeout(BRUTAL_NEGOTIATION_TIMEOUT, async {
        let (mut send, mut recv, _id) = sq_conn.open_bi().await?;
        SQReq::SQExtension(SQExtOpcode::MihomoBrutal(BrutalNegotiation {
            flags: 0,
            rx: rates.down.map(bits_to_wire).unwrap_or(0),
        }))
        .encode(&mut send)
        .await?;
        BrutalNegotiation::decode(&mut recv).await
    })
    .await
    .map_err(|_| SError::from(std::io::Error::from(std::io::ErrorKind::TimedOut)))??;

    let mode = client_decision(&rates, &response);
    sq_conn.set_brutal_send_mode(mode);
    info!(
        event = "recovery:brutal_negotiated",
        server_rx_bps = wire_to_bits(response.rx),
        rx_auto = response.rx_auto(),
        ?mode,
        "brutal negotiated with server"
    );
    Ok(Some(mode))
}

#[cfg(test)]
mod tests {
    use super::*;
    use BrutalSendMode::{Base, Brutal};

    const MBIT: u64 = 1_000_000;

    fn rates(up: Option<u64>, down: Option<u64>) -> BrutalRates {
        BrutalRates { up, down }
    }

    fn response(rx_bits: u64, auto: bool) -> BrutalNegotiation {
        BrutalNegotiation {
            flags: if auto {
                BRUTAL_NEGOTIATION_FLAG_RX_AUTO
            } else {
                0
            },
            rx: rx_bits / 8,
        }
    }

    #[test]
    fn server_without_bandwidth_uses_client_rate_uncapped() {
        let (mode, resp) = server_decision(&rates(None, None), 200 * MBIT / 8, false);
        assert_eq!(mode, Brutal(200 * MBIT));
        assert_eq!(resp, response(0, false));
    }

    #[test]
    fn server_caps_client_rate_with_bandwidth() {
        let server = rates(Some(100 * MBIT), Some(80 * MBIT));
        let (mode, resp) = server_decision(&server, 200 * MBIT / 8, false);
        assert_eq!(mode, Brutal(100 * MBIT));
        assert_eq!(resp, response(80 * MBIT, false));
        let (mode, _) = server_decision(&server, 50 * MBIT / 8, false);
        assert_eq!(mode, Brutal(50 * MBIT));
    }

    #[test]
    fn server_uses_base_without_client_rate() {
        let (mode, _) = server_decision(&rates(Some(100 * MBIT), None), 0, false);
        assert_eq!(mode, Base);
    }

    #[test]
    fn server_ignoring_client_bandwidth_answers_auto() {
        let server = rates(Some(100 * MBIT), Some(80 * MBIT));
        let (mode, resp) = server_decision(&server, 200 * MBIT / 8, true);
        assert_eq!(mode, Base);
        assert!(resp.rx_auto());
    }

    #[test]
    fn client_caps_upload_with_server_rx() {
        let client = rates(Some(100 * MBIT), Some(200 * MBIT));
        assert_eq!(
            client_decision(&client, &response(20 * MBIT, false)),
            Brutal(20 * MBIT)
        );
        assert_eq!(
            client_decision(&client, &response(500 * MBIT, false)),
            Brutal(100 * MBIT)
        );
    }

    #[test]
    fn client_uses_own_bandwidth_when_server_has_no_limit() {
        let client = rates(Some(100 * MBIT), None);
        assert_eq!(
            client_decision(&client, &response(0, false)),
            Brutal(100 * MBIT)
        );
    }

    #[test]
    fn client_without_bandwidth_stays_on_base() {
        let client = rates(None, Some(200 * MBIT));
        assert_eq!(client_decision(&client, &response(20 * MBIT, false)), Base);
    }

    #[test]
    fn client_uses_base_on_auto() {
        let client = rates(Some(100 * MBIT), Some(200 * MBIT));
        assert_eq!(client_decision(&client, &response(20 * MBIT, true)), Base);
    }

    #[test]
    fn huge_wire_rate_saturates() {
        let (mode, _) = server_decision(&rates(None, None), u64::MAX, false);
        assert_eq!(mode, Brutal(u64::MAX));
    }
}
