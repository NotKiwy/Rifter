#![allow(non_camel_case_types)]

mod cli;
mod discovery;
mod parser;
mod store;
mod validator;

use anyhow::Result;
use clap::Parser;
use cli::{_cli, _cmd, _fmt, _proto};
use discovery::_hub;
use parser::_kind;

#[tokio::main]
async fn main() -> Result<()> {
    let _cli = _cli::parse();

    match _cli._cmd {
        _cmd::Crawl {
            _token,
            _protocols,
            _max_results,
            _concurrency,
            _timeout,
            _output,
            _dry_run,
        } => __gopher(_token, _protocols, _max_results, _concurrency, _timeout, _output, _dry_run).await,

        _cmd::Validate { _input, _concurrency, _timeout, _prune } => {
            __sentinel(_input, _concurrency, _timeout, _prune).await
        }

        _cmd::Search { _input, _protocol, _max_ping, _host, _limit } => {
            __sift(_input, _protocol, _max_ping, _host, _limit)
        }

        _cmd::Export { _input, _format, _limit } => __spit(_input, _format, _limit),
    }
}

fn __widen(_protocols: &[_proto]) -> Vec<_kind> {
    let ___wants_all = _protocols.is_empty() || _protocols.contains(&_proto::All);
    if ___wants_all {
        return vec![_kind::Vless, _kind::Trojan, _kind::Shadowsocks, _kind::Hysteria2];
    }
    _protocols
        .iter()
        .filter_map(|_p| match _p {
            _proto::Vless => Some(_kind::Vless),
            _proto::Trojan => Some(_kind::Trojan),
            _proto::Ss => Some(_kind::Shadowsocks),
            _proto::Hysteria2 => Some(_kind::Hysteria2),
            _proto::All => None,
        })
        .collect()
}

async fn __gopher(
    _token: String,
    _protocols: Vec<_proto>,
    _max_results: usize,
    _concurrency: usize,
    _timeout: u64,
    _output: String,
    _dry_run: bool,
) -> Result<()> {
    let _kinds = __widen(&_protocols);
    let _hub = _hub::__spawn(_token)?;

    let mut _all = Vec::new();
    for _kind in &_kinds {
        eprintln!("discovering {_kind} configs on GitHub...");
        match _hub.__excavate(*_kind, _max_results).await {
            Ok(mut _found) => {
                eprintln!("  found {} {_kind} config(s)", _found.len());
                _all.append(&mut _found);
            }
            Err(_e) => eprintln!("  discovery failed for {_kind}: {_e:#}"),
        }
    }

    let mut _all = store::__dedupe(_all);
    eprintln!("{} unique config(s) after dedup", _all.len());

    if _dry_run {
        eprintln!("--dry-run set, skipping liveness validation");
    } else {
        eprintln!("validating reachability (concurrency={_concurrency}, timeout={_timeout}ms)...");
        validator::__sweep(&mut _all, _concurrency, _timeout).await;
    }

    store::__save_all(&_all, &_output)?;
    let ___alive = _all.iter().filter(|_r| _r._alive == Some(true)).count();
    eprintln!("saved {} config(s) to {_output} ({___alive} confirmed alive)", _all.len());
    Ok(())
}

async fn __sentinel(_input: String, _concurrency: usize, _timeout: u64, _prune: bool) -> Result<()> {
    let mut _relays = store::__load(&_input)?;
    eprintln!("loaded {} config(s) from {_input}", _relays.len());

    validator::__sweep(&mut _relays, _concurrency, _timeout).await;

    if _prune {
        let ___before = _relays.len();
        _relays.retain(|_r| _r._alive == Some(true));
        eprintln!("pruned {} dead config(s)", ___before - _relays.len());
    }

    store::__save_single(&_input, &_relays)?;
    let ___alive = _relays.iter().filter(|_r| _r._alive == Some(true)).count();
    eprintln!("saved {} config(s) back to {_input} ({___alive} alive)", _relays.len());
    Ok(())
}

fn __sift(
    _input: String,
    _protocol: Option<_proto>,
    _max_ping: Option<u64>,
    _host: Option<String>,
    _limit: usize,
) -> Result<()> {
    let mut _relays = store::__load(&_input)?;

    if let Some(_p) = _protocol {
        let _wanted = __widen(&[_p]);
        _relays.retain(|_r| _wanted.contains(&_r._kind));
    }
    if let Some(_max_ping) = _max_ping {
        _relays.retain(|_r| _r._ping_ms.map(|_p| _p <= _max_ping).unwrap_or(false));
    }
    if let Some(_host) = &_host {
        _relays.retain(|_r| _r._addr.contains(_host.as_str()));
    }
    _relays.truncate(_limit);

    __slab(&_relays);
    Ok(())
}

fn __spit(_input: String, _format: _fmt, _limit: usize) -> Result<()> {
    let mut _relays = store::__load(&_input)?;
    _relays.truncate(_limit);

    match _format {
        _fmt::Table => __slab(&_relays),
        _fmt::Json => println!("{}", serde_json::to_string_pretty(&_relays)?),
    }
    Ok(())
}

fn __slab(_relays: &[parser::_relay]) {
    if _relays.is_empty() {
        println!("no configs to show");
        return;
    }
    println!(
        "{:<11} {:<32} {:>6} {:>8} {:<8} {}",
        "PROTOCOL", "HOST", "PORT", "PING", "ALIVE", "TAG"
    );
    for _r in _relays {
        let ___ping = _r._ping_ms.map(|_p| format!("{_p}ms")).unwrap_or_else(|| "-".to_string());
        let ___alive = match _r._alive {
            Some(true) => "yes",
            Some(false) => "no",
            None => "?",
        };
        println!(
            "{:<11} {:<32} {:>6} {:>8} {:<8} {}",
            _r._kind.__as_str(),
            _r._addr,
            _r._port,
            ___ping,
            ___alive,
            _r._tag
        );
    }
}
