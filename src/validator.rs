#![allow(non_camel_case_types, non_upper_case_globals)]

use crate::parser::_relay;
use futures::stream::{self, StreamExt};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

pub async fn __sweep(_relays: &mut [_relay], _concurrency: usize, _timeout_ms: u64) {
    let _timeout = Duration::from_millis(_timeout_ms);
    let _total = _relays.len();
    if _total == 0 {
        return;
    }

    let _targets: Vec<(usize, String, u16)> =
        _relays.iter().enumerate().map(|(_i, _r)| (_i, _r._addr.clone(), _r._port)).collect();

    let _checks = _targets.into_iter().map(|(_i, _addr, _port)| async move {
        let ___start = Instant::now();
        let _outcome = tokio::time::timeout(_timeout, TcpStream::connect((_addr.as_str(), _port))).await;
        match _outcome {
            Ok(Ok(_)) => (_i, true, Some(___start.elapsed().as_millis() as u64)),
            _ => (_i, false, None),
        }
    });

    let mut _stream = stream::iter(_checks).buffer_unordered(_concurrency.max(1));
    let ___now = chrono::Utc::now().to_rfc3339();
    let mut _done = 0usize;
    let mut _alive_count = 0usize;
    
    while let Some((_i, _alive, _ping)) = _stream.next().await {
        _relays[_i]._alive = Some(_alive);
        _relays[_i]._ping_ms = _ping;
        _relays[_i]._checked_at = Some(___now.clone());
        if _alive {
            _alive_count += 1;
        }
        _done += 1;
        if _done % 50 == 0 || _done == _total {
            eprintln!("  validated {_done}/{_total} ({_alive_count} alive)");
        }
    }
}
