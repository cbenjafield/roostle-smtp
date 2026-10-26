use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{info, warn};

use crate::session::{self, Mode, Shared};

pub async fn bind(addrs: &[SocketAddr]) -> Result<Vec<TcpListener>> {
    let mut listeners = Vec::new();
    for addr in addrs {
        listeners.push(TcpListener::bind(addr).await.with_context(|| format!("binding {addr}"))?);
    }
    Ok(listeners)
}

pub async fn serve(
    listener: TcpListener,
    mode: Mode,
    shared: Arc<Shared>,
    permits: Arc<Semaphore>,
    tracker: TaskTracker,
    shutdown: CancellationToken,
) {
    let local = listener.local_addr().ok();
    info!(?mode, addr = ?local, "listening");
    loop {
        let (stream, peer) = tokio::select! {
            _ = shutdown.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok(c) => c,
                Err(e) => {
                    warn!(error = %e, "accept failed");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            tracker.spawn(refuse(stream));
            continue;
        };
        let shared = shared.clone();
        tracker.spawn(async move {
            let _permit = permit;
            let _ = stream.set_nodelay(true);
            session::handle(shared, mode, Box::new(stream), peer.ip().to_canonical()).await;
        });
    }
    info!(?mode, addr = ?local, "listener stopped");
}

async fn refuse(mut stream: TcpStream) {
    let _ = stream.write_all(b"421 4.3.2 Too many connections, try again later\r\n").await;
}
