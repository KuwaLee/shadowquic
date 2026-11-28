//! A ShadowQUIC server paces a negotiated Brutal download at the requested
//! rate, like Hysteria2, instead of deriving its rate from the window, and
//! keeps that rate when the client moves to a new address.

#![cfg(feature = "shadowquic-quinn")]

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use shadowquic::{
    Manager,
    config::{
        AuthUser, BrutalParams, CongestionControl, DirectOutCfg, JlsUpstream, PortHoppingCfg,
        ShadowQuicClientCfg, ShadowQuicServerCfg, default_initial_mtu,
    },
    direct::outbound::DirectOut,
    msgs::{SEncode, socks5::SocksAddr, squic::SQReq},
    quic::{BrutalSendMode, QuicConnection, QuicServer},
    shadowquic::{EndServer, inbound::ShadowQuicServer, outbound::ShadowQuicClient},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::{Instant, timeout},
};

const DOWN_BPS: u64 = 40_000_000;

/// Upstream that writes zeros to every connection.
async fn start_bulk_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let chunk = vec![0u8; 64 * 1024];
                while stream.write_all(&chunk).await.is_ok() {}
            });
        }
    });
    addr
}

/// Reads some bytes, failing the test if the download stalls or ends.
async fn read_some(recv: &mut (impl AsyncRead + Unpin), buf: &mut [u8]) -> u64 {
    let n = timeout(Duration::from_secs(1), recv.read(buf))
        .await
        .expect("download stalled")
        .unwrap();
    assert!(n > 0, "download ended");
    n as u64
}

/// Brutal counts QUIC packets, so the payload is a few percent below the
/// rate.
fn assert_near_down(bps: f64) {
    let target = DOWN_BPS as f64;
    assert!(
        (0.85 * target..=1.02 * target).contains(&bps),
        "received {:.1} Mbit/s, requested {:.1} Mbit/s",
        bps / 1e6,
        target / 1e6
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn negotiated_brutal_download_is_paced_at_requested_rate() {
    let upstream = start_bulk_upstream().await;

    // The server has no send rate and negotiates the client's. Loopback RTTs
    // are tens of microseconds, where twice the bandwidth-delay product is
    // below a datagram: like Hysteria2, Brutal still keeps two datagrams in
    // flight, so the receiver acknowledges without waiting for its ACK delay.
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
        congestion_control: CongestionControl::Brutal(BrutalParams::default()),
        ..Default::default()
    })
    .await
    .unwrap();
    let server_addr = sq_server.endpoint.local_addr().unwrap();
    let direct = DirectOut::new(
        DirectOutCfg {
            tag: "outbound".into(),
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
            congestion_control: CongestionControl::Brutal(BrutalParams {
                down: Some(DOWN_BPS),
                ..Default::default()
            }),
            ..Default::default()
        },
        Arc::new(shadowquic::dns::ResolverManager::new()),
    );
    // Connecting starts the negotiation in the background.
    let conn = sq_client.get_conn().await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let (mut send, mut recv, _) = QuicConnection::open_bi(&***conn).await.unwrap();
    SQReq::SQConnect(SocksAddr::from(upstream))
        .encode(&mut send)
        .await
        .unwrap();
    send.flush().await.unwrap();

    // Skip the initial burst, then measure for two seconds.
    let mut buf = vec![0u8; 256 * 1024];
    let warmup = Instant::now() + Duration::from_millis(500);
    while Instant::now() < warmup {
        read_some(&mut recv, &mut buf).await;
    }
    let start = Instant::now();
    let mut received = 0;
    while start.elapsed() < Duration::from_secs(2) {
        received += read_some(&mut recv, &mut buf).await;
    }
    let bps = received as f64 * 8.0 / start.elapsed().as_secs_f64();
    eprintln!("received {:.1} Mbit/s", bps / 1e6);
    // With window-based pacing, the tiny loopback RTT sends far above the
    // rate; with a window of one datagram, far below it.
    assert_near_down(bps);

    recv.stop(0u32.into()).unwrap();
    server_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn brutal_rate_survives_client_port_change() {
    // quinn resets congestion control when an IPv6 peer changes port. Like a
    // Hysteria2 server, the ShadowQUIC server keeps the Brutal rate set by
    // negotiation instead of falling back to BBR, which would send far above
    // it.
    let user = AuthUser {
        username: "user".into(),
        password: "pass".into(),
    };
    let server = EndServer::new(&ShadowQuicServerCfg {
        bind_addr: "[::1]:0".parse().unwrap(),
        users: vec![user.clone()],
        jls_upstream: JlsUpstream {
            addr: "localhost:443".into(),
            ..Default::default()
        },
        alpn: vec!["h3".into()],
        congestion_control: CongestionControl::Brutal(BrutalParams::default()),
        ..Default::default()
    })
    .await
    .unwrap();
    let client = ShadowQuicClient::new(
        ShadowQuicClientCfg {
            addr: server.local_addr().unwrap().to_string(),
            server_name: "localhost".into(),
            username: user.username,
            password: user.password,
            alpn: vec!["h3".into()],
            port_hopping: PortHoppingCfg {
                enable: true,
                interval: 1_000.into(),
                interval_jitter: 0.into(),
            },
            ..Default::default()
        },
        Arc::new(shadowquic::dns::ResolverManager::new()),
    );

    let (client_conn, server_conn) = timeout(Duration::from_secs(5), async {
        tokio::join!(client.get_conn(), QuicServer::accept(&server))
    })
    .await
    .expect("timed out connecting");
    let client_conn = client_conn.unwrap();
    let server_conn = server_conn.unwrap();
    let mut addresses = server_conn.watch_remote_address();
    let first_port = server_conn.remote_address().port();
    // What the server's negotiation handler does for a client asking for
    // `DOWN_BPS` when the server has no `bandwidth`.
    assert!(server_conn.set_brutal_send_mode(BrutalSendMode::Brutal(DOWN_BPS)));

    // The server streams zeros to the client, which counts what arrives.
    let (mut client_send, mut client_recv) = client_conn.open_bi().await.unwrap();
    client_send.write_all(b"a").await.unwrap();
    let (mut server_send, mut server_recv) =
        timeout(Duration::from_secs(5), server_conn.accept_bi())
            .await
            .expect("timed out accepting the stream")
            .unwrap();
    let mut request = [0];
    server_recv.read_exact(&mut request).await.unwrap();
    let writer = tokio::spawn(async move {
        let chunk = vec![0u8; 64 * 1024];
        while server_send.write_all(&chunk).await.is_ok() {}
    });
    let received = Arc::new(AtomicU64::new(0));
    let reader = tokio::spawn({
        let received = received.clone();
        async move {
            let mut buf = vec![0u8; 256 * 1024];
            while let Ok(Some(n)) = client_recv.read(&mut buf).await {
                received.fetch_add(n as u64, Ordering::Relaxed);
            }
        }
    });

    // Measure once the server has moved the connection to a new client port.
    let address = timeout(Duration::from_secs(5), addresses.wait())
        .await
        .expect("server did not observe a new client port")
        .expect("connection closed while waiting for a port change");
    assert_ne!(address.port(), first_port);
    let before = received.load(Ordering::Relaxed);
    let start = Instant::now();
    tokio::time::sleep(Duration::from_secs(2)).await;
    let bps =
        (received.load(Ordering::Relaxed) - before) as f64 * 8.0 / start.elapsed().as_secs_f64();
    eprintln!("received {:.1} Mbit/s after a port change", bps / 1e6);
    assert!(!reader.is_finished(), "download ended");
    // The server is still sending to a new port, not back on the first one.
    assert_ne!(server_conn.remote_address().port(), first_port);
    assert_near_down(bps);

    writer.abort();
    reader.abort();
}
