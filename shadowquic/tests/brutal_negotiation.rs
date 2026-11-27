use std::sync::Arc;
use std::time::Duration;

use shadowquic::Inbound;
use shadowquic::config::{
    AuthUser, BrutalParams, CongestionControl, JlsUpstream, ShadowQuicClientCfg,
    ShadowQuicServerCfg, default_initial_mtu,
};
use shadowquic::quic::BrutalSendMode;
use shadowquic::shadowquic::{inbound::ShadowQuicServer, outbound::ShadowQuicClient};
use shadowquic::squic::{brutal::negotiate, outbound::get_peer_conn_stats};

const MBIT: u64 = 1_000_000;

fn brutal(up: Option<u64>, down: Option<u64>) -> CongestionControl {
    CongestionControl::Brutal(BrutalParams {
        bandwidth: up,
        down,
        ..Default::default()
    })
}

async fn start_server(
    port: u16,
    congestion_control: CongestionControl,
    ignore_client_bandwidth: bool,
) {
    let server = ShadowQuicServer::new(ShadowQuicServerCfg {
        bind_addr: format!("127.0.0.1:{port}").parse().unwrap(),
        users: vec![AuthUser {
            username: "123".into(),
            password: "123".into(),
        }],
        jls_upstream: JlsUpstream {
            addr: "localhost:443".into(),
            ..Default::default()
        },
        alpn: vec!["h3".into()],
        initial_mtu: default_initial_mtu(),
        congestion_control,
        ignore_client_bandwidth,
        ..Default::default()
    })
    .await
    .unwrap();
    server.init().await.expect("failed to initialize server");
    tokio::time::sleep(Duration::from_millis(100)).await;
}

fn client(port: u16, congestion_control: CongestionControl) -> ShadowQuicClient {
    ShadowQuicClient::new(
        ShadowQuicClientCfg {
            tag: "outbound".into(),
            password: "123".into(),
            username: "123".into(),
            addr: format!("127.0.0.1:{port}"),
            server_name: "localhost".into(),
            alpn: vec!["h3".into()],
            initial_mtu: 1200,
            congestion_control,
            ..Default::default()
        },
        Arc::new(shadowquic::dns::ResolverManager::new()),
    )
}

async fn negotiated_upload(
    port: u16,
    server_cc: CongestionControl,
    ignore_client_bandwidth: bool,
    client_cc: CongestionControl,
) -> Option<BrutalSendMode> {
    start_server(port, server_cc, ignore_client_bandwidth).await;
    let conn = client(port, client_cc)
        .get_conn()
        .await
        .expect("failed to connect");
    let mode = negotiate(&conn).await.expect("negotiation failed");
    let stats = get_peer_conn_stats(&conn).await.expect("connection broken");
    assert!(stats.is_ok());
    mode
}

#[tokio::test]
async fn client_upload_is_capped_by_server_down() {
    let mode = negotiated_upload(
        4493,
        brutal(Some(100 * MBIT), Some(20 * MBIT)),
        false,
        brutal(Some(50 * MBIT), Some(200 * MBIT)),
    )
    .await;
    assert_eq!(mode, Some(BrutalSendMode::Brutal(20 * MBIT)));
}

#[tokio::test]
async fn server_without_rates_lets_client_use_its_bandwidth() {
    let mode = negotiated_upload(
        4494,
        CongestionControl::Bbr,
        false,
        brutal(Some(50 * MBIT), Some(200 * MBIT)),
    )
    .await;
    assert_eq!(mode, Some(BrutalSendMode::Brutal(50 * MBIT)));
}

#[tokio::test]
async fn server_ignoring_client_bandwidth_sends_client_to_base() {
    let mode = negotiated_upload(
        4495,
        brutal(Some(100 * MBIT), Some(20 * MBIT)),
        true,
        brutal(Some(50 * MBIT), Some(200 * MBIT)),
    )
    .await;
    assert_eq!(mode, Some(BrutalSendMode::Base));
}

#[tokio::test]
async fn client_without_brutal_rates_does_not_negotiate() {
    let mode = negotiated_upload(
        4496,
        brutal(Some(100 * MBIT), Some(20 * MBIT)),
        false,
        CongestionControl::Bbr,
    )
    .await;
    assert_eq!(mode, None);
}
