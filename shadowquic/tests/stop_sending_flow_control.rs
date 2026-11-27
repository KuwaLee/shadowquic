#[cfg(feature = "shadowquic-quinn")]
use std::{net::SocketAddr, sync::Arc, time::Duration};

#[cfg(feature = "shadowquic-quinn")]
use shadowquic::{
    Manager,
    config::{AuthUser, CongestionControl, DirectOutCfg, default_initial_mtu},
    direct::outbound::DirectOut,
    msgs::{SEncode, socks5::SocksAddr, squic::SQReq},
    quic::QuicConnection,
};
#[cfg(feature = "shadowquic-quinn")]
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    time::timeout,
};

#[cfg(feature = "shadowquic-quinn")]
async fn start_upstream_server() -> (
    SocketAddr,
    oneshot::Receiver<()>,
    oneshot::Receiver<()>,
    oneshot::Receiver<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (bulk_closed_tx, bulk_closed_rx) = oneshot::channel();
    let (stop_written_tx, stop_written_rx) = oneshot::channel();
    let (stop_closed_tx, stop_closed_rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut bulk_closed_tx = Some(bulk_closed_tx);
        let mut stop_written_tx = Some(stop_written_tx);
        let mut stop_closed_tx = Some(stop_closed_tx);

        while let Ok((mut stream, _)) = listener.accept().await {
            let mut tag = [0u8; 4];
            if stream.read_exact(&mut tag).await.is_err() {
                continue;
            }
            match &tag {
                b"BULK" => {
                    let closed_tx = bulk_closed_tx.take();
                    tokio::spawn(async move {
                        let (mut r, mut w) = stream.into_split();
                        let writer = tokio::spawn(async move {
                            let chunk = vec![0xABu8; 16 * 1024];
                            while w.write_all(&chunk).await.is_ok() {}
                        });
                        let mut buf = [0u8; 64];
                        while matches!(r.read(&mut buf).await, Ok(n) if n > 0) {}
                        writer.abort();
                        if let Some(tx) = closed_tx {
                            let _ = tx.send(());
                        }
                    });
                }
                b"STOP" => {
                    let written_tx = stop_written_tx.take();
                    let closed_tx = stop_closed_tx.take();
                    tokio::spawn(async move {
                        // Send enough data that the server's QUIC SendStream must
                        // call poll_write while the connection window is exhausted.
                        let payload = vec![0xCDu8; 16 * 1024];
                        let _ = stream.write_all(&payload).await;
                        if let Some(tx) = written_tx {
                            let _ = tx.send(());
                        }
                        // Wait for the proxy server to drop this upstream TCP socket.
                        let mut buf = [0u8; 64];
                        loop {
                            match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(_) => {}
                            }
                        }
                        if let Some(tx) = closed_tx {
                            let _ = tx.send(());
                        }
                    });
                }
                b"PING" => {
                    tokio::spawn(async move {
                        let _ = stream.write_all(b"PONG").await;
                        let _ = stream.shutdown().await;
                    });
                }
                _ => {}
            }
        }
    });

    (addr, bulk_closed_rx, stop_written_rx, stop_closed_rx)
}

#[cfg(feature = "shadowquic-quinn")]
#[tokio::test]
async fn shadowquic_stop_sending_unblocks_blocked_writer_under_exhausted_max_data() {
    use shadowquic::{
        config::{JlsUpstream, ShadowQuicClientCfg, ShadowQuicServerCfg},
        shadowquic::{inbound::ShadowQuicServer, outbound::ShadowQuicClient},
    };

    let (upstream_addr, bulk_closed_rx, stop_written_rx, stop_closed_rx) =
        start_upstream_server().await;

    let sq_server = ShadowQuicServer::new(ShadowQuicServerCfg {
        tag: "inbound".into(),
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        users: vec![AuthUser {
            username: "user".into(),
            password: "pass".into(),
        }],
        jls_upstream: JlsUpstream {
            addr: "localhost:443".into(),
            ..Default::default()
        },
        alpn: vec!["h3".into()],
        zero_rtt: false,
        initial_mtu: default_initial_mtu(),
        congestion_control: CongestionControl::Bbr,
        ..Default::default()
    })
    .await
    .unwrap();
    let server_addr = sq_server.endpoint.local_addr().unwrap();

    // Keep the default 60s half-close timeout so a stalled writer cannot hide
    // behind a short test timeout.
    let direct = DirectOut::new(
        DirectOutCfg {
            tag: "outbound".into(),
            half_close_timeout: 60_000,
            ..Default::default()
        },
        Arc::new(shadowquic::dns::ResolverManager::new()),
    );
    let server_task = tokio::spawn(Manager::single(Box::new(sq_server), Arc::new(direct)).run());
    tokio::time::sleep(Duration::from_millis(50)).await;

    let sq_client = ShadowQuicClient::new(
        ShadowQuicClientCfg {
            tag: "outbound".into(),
            username: "user".into(),
            password: "pass".into(),
            addr: server_addr.to_string(),
            server_name: "localhost".into(),
            alpn: vec!["h3".into()],
            zero_rtt: false,
            initial_mtu: 1200,
            congestion_control: CongestionControl::Bbr,
            // Small connection receive window so a single unread bulk stream
            // reliably drives the server's write_limit() to 0.
            stream_receive_window: 64 * 1024,
            receive_window: Some(64 * 1024),
            ..Default::default()
        },
        Arc::new(shadowquic::dns::ResolverManager::new()),
    );

    let conn = sq_client.get_conn().await.unwrap();
    let dst = SocksAddr::from(upstream_addr);

    // Stream 1: fill the client's 64 KiB connection MAX_DATA window and leave it unread.
    let (mut bulk_send, mut bulk_recv, _) = QuicConnection::open_bi(&***conn).await.unwrap();
    SQReq::SQConnect(dst.clone())
        .encode(&mut bulk_send)
        .await
        .unwrap();
    bulk_send.write_all(b"BULK").await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Stream 2: open a request while write_limit() == 0, then send STOP_SENDING(0).
    let (mut stop_send, mut stop_recv, _) = QuicConnection::open_bi(&***conn).await.unwrap();
    SQReq::SQConnect(dst.clone())
        .encode(&mut stop_send)
        .await
        .unwrap();
    stop_send.write_all(b"STOP").await.unwrap();

    timeout(Duration::from_secs(2), stop_written_rx)
        .await
        .expect("upstream did not receive STOP request")
        .unwrap();
    // Give the server relay task a moment to enter SendStream::poll_write and block.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send STOP_SENDING(0) without closing the write side yet; the server must
    // react immediately instead of blocking until MAX_DATA increases or the 60s
    // half-close timeout expires.
    stop_recv.stop(0u32.into()).unwrap();

    timeout(Duration::from_secs(2), stop_closed_rx)
        .await
        .expect("server writer stayed deadlocked after STOP_SENDING while MAX_DATA == 0")
        .unwrap();

    // Now stop the bulk stream too and verify the connection recovers cleanly
    // for a fresh ping request.
    bulk_recv.stop(0u32.into()).unwrap();
    timeout(Duration::from_secs(2), bulk_closed_rx)
        .await
        .expect("bulk stream did not close after STOP_SENDING")
        .unwrap();

    let (mut ping_send, mut ping_recv, _) = QuicConnection::open_bi(&***conn).await.unwrap();
    SQReq::SQConnect(dst).encode(&mut ping_send).await.unwrap();
    ping_send.write_all(b"PING").await.unwrap();
    ping_send.shutdown().await.unwrap();

    let mut pong = [0u8; 4];
    timeout(Duration::from_secs(2), ping_recv.read_exact(&mut pong))
        .await
        .expect("ping timed out after stopping bulk streams")
        .unwrap();
    assert_eq!(&pong, b"PONG");

    server_task.abort();
}
