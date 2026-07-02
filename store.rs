#![allow(non_camel_case_types, non_upper_case_globals)]

use crate::parser::{_kind, _relay};
use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub fn __dedupe(_relays: Vec<_relay>) -> Vec<_relay> {
    let mut ___seen: HashSet<(String, String, u16)> = HashSet::new();
    let mut _out: Vec<_relay> = Vec::new();

    for _relay in _relays {
        let _key = (_relay._kind.__as_str().to_string(), _relay._addr.clone(), _relay._port);
        if ___seen.contains(&_key) {
            if _relay._alive == Some(true) {
                if let Some(_existing) = _out.iter_mut().find(|_r| {
                    _r._kind == _relay._kind && _r._addr == _relay._addr && _r._port == _relay._port
                }) {
                    if _existing._alive != Some(true) {
                        *_existing = _relay;
                    }
                }
            }
            continue;
        }
        ___seen.insert(_key);
        _out.push(_relay);
    }

    _out
}

pub fn __load(_path: impl AsRef<Path>) -> Result<Vec<_relay>> {
    let _path = _path.as_ref();
    if !_path.exists() {
        return Ok(Vec::new());
    }
    let _raw = std::fs::read_to_string(_path).with_context(|| format!("reading {}", _path.display()))?;
    if _raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    let _relays: Vec<_relay> = serde_json::from_str(&_raw).with_context(|| format!("parsing {}", _path.display()))?;
    Ok(_relays)
}

#[derive(Serialize)]
struct ___meta {
    updated_at: String,
    total: usize,
    alive: usize,
}

fn __spill(_path: &Path, _relays: &[_relay]) -> Result<()> {
    if let Some(_parent) = _path.parent() {
        if !_parent.as_os_str().is_empty() {
            std::fs::create_dir_all(_parent).with_context(|| format!("creating {}", _parent.display()))?;
        }
    }
    let _body = serde_json::to_string_pretty(_relays)?;
    std::fs::write(_path, _body).with_context(|| format!("writing {}", _path.display()))?;
    Ok(())
}

pub fn __save_single(_path: impl AsRef<Path>, _relays: &[_relay]) -> Result<()> {
    __spill(_path.as_ref(), _relays)
}

pub fn __save_all(_relays: &[_relay], _output_path: &str) -> Result<()> {
    let _output_path = PathBuf::from(_output_path);
    let _dir = _output_path
        .parent()
        .filter(|_p| !_p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    let _kept: Vec<_relay> = _relays.iter().filter(|_r| _r._alive != Some(false)).cloned().collect();

    __spill(&_output_path, &_kept)?;

    for _kind in [_kind::Vless, _kind::Trojan, _kind::Shadowsocks, _kind::Hysteria2] {
        let _subset: Vec<_relay> = _kept.iter().filter(|_r| _r._kind == _kind).cloned().collect();
        __spill(&_dir.join(format!("{}.json", _kind.__as_str())), &_subset)?;
    }

    let ___meta = ___meta {
        updated_at: chrono::Utc::now().to_rfc3339(),
        total: _kept.len(),
        alive: _kept.iter().filter(|_r| _r._alive == Some(true)).count(),
    };
    std::fs::write(_dir.join("meta.json"), serde_json::to_string_pretty(&___meta)?)
        .with_context(|| format!("writing {}", _dir.join("meta.json").display()))?;

    Ok(())
}
