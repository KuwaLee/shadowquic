use std::sync::Arc;
use std::time::Duration;

use shadowquic::Inbound;
use shadowquic::config::{
    AuthUser, BrutalParams, CongestionControl, JlsUpstream, ShadowQuicClientCfg,
    ShadowQuicServerCfg, default_initial_mtu,
};
use shadowquic::shadowquic::{inbound::ShadowQuicServer, outbound::ShadowQuicClient};
use shadowquic::squic::{brutal::negotiate, outbound::get_peer_conn_stats};

const MBIT: u64 = 1_000_000;

fn brutal(up: u64, down: Option<u64>) -> CongestionControl {
    CongestionControl::Brutal(BrutalParams {
        bandwidth: up,
        down,
        ..Default::default()
    })
}

async fn start_server(port: u16, congestion_control: CongestionControl) {
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

#[tokio::test]
async fn client_upload_is_capped_by_server_down() {
    start_server(4493, brutal(100 * MBIT, Some(20 * MBIT))).await;
    let conn = client(4493, brutal(50 * MBIT, Some(200 * MBIT)))
        .get_conn()
        .await
        .expect("failed to connect");

    let rate = negotiate(&conn).await.expect("negotiation failed");
    assert_eq!(rate, Some(20 * MBIT));
}

#[tokio::test]
async fn client_keeps_upload_when_server_reports_no_down() {
    start_server(4494, brutal(100 * MBIT, None)).await;
    let conn = client(4494, brutal(50 * MBIT, Some(200 * MBIT)))
        .get_conn()
        .await
        .expect("failed to connect");

    let rate = negotiate(&conn).await.expect("negotiation failed");
    assert_eq!(rate, None);
}

#[tokio::test]
async fn negotiation_fails_without_breaking_connection_when_server_is_not_brutal() {
    start_server(4495, CongestionControl::Bbr).await;
    let conn = client(4495, brutal(50 * MBIT, Some(200 * MBIT)))
        .get_conn()
        .await
        .expect("failed to connect");

    assert!(negotiate(&conn).await.is_err());
    let stats = get_peer_conn_stats(&conn).await.expect("connection broken");
    assert!(stats.is_ok());
}

#[tokio::test]
async fn client_without_down_does_not_negotiate() {
    start_server(4496, brutal(100 * MBIT, Some(20 * MBIT))).await;
    let conn = client(4496, brutal(50 * MBIT, None))
        .get_conn()
        .await
        .expect("failed to connect");

    assert_eq!(negotiate(&conn).await.expect("unexpected error"), None);
}
