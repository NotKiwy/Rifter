#![allow(non_camel_case_types)]

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum _kind {
    Vless,
    Trojan,
    Shadowsocks,
    Hysteria2,
}

impl _kind {
    pub fn as_str(&self) -> &'static str {
        match self {
            _kind::Vless => "vless",
            _kind::Trojan => "trojan",
            _kind::Shadowsocks => "shadowsocks",
            _kind::Hysteria2 => "hysteria2",
        }
    }
}

impl std::fmt::Display for _kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for _kind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "vless" => Ok(_kind::Vless),
            "trojan" => Ok(_kind::Trojan),
            "ss" | "shadowsocks" => Ok(_kind::Shadowsocks),
            "hysteria2" | "hy2" => Ok(_kind::Hysteria2),
            other => Err(format!("unknown protocol: {other}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct _relay {
    #[serde(rename = "protocol")]
    pub _kind: _kind,
    #[serde(rename = "host")]
    pub _addr: String,
    #[serde(rename = "port")]
    pub _port: u16,
    #[serde(rename = "secret")]
    pub _secret: String,
    #[serde(rename = "tag")]
    pub _tag: String,
    #[serde(rename = "extra", default, skip_serializing_if = "HashMap::is_empty")]
    pub _extra: HashMap<String, String>,

    // Populated later in the pipeline (discovery / validation), not by the parser itself.
    #[serde(rename = "source_repo", default, skip_serializing_if = "Option::is_none")]
    pub source_repo: Option<String>,
    #[serde(rename = "source_path", default, skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
    #[serde(rename = "alive", default, skip_serializing_if = "Option::is_none")]
    pub alive: Option<bool>,
    #[serde(rename = "ping_ms", default, skip_serializing_if = "Option::is_none")]
    pub ping_ms: Option<u64>,
    #[serde(rename = "checked_at", default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<String>,
}

fn __scheme_sniff(_uri: &str) -> Option<_kind> {
    let ___lower = _uri.to_ascii_lowercase();
    if ___lower.starts_with("vless://") {
        Some(_kind::Vless)
    } else if ___lower.starts_with("trojan://") {
        Some(_kind::Trojan)
    } else if ___lower.starts_with("ss://") {
        Some(_kind::Shadowsocks)
    } else if ___lower.starts_with("hysteria2://") || ___lower.starts_with("hy2://") {
        Some(_kind::Hysteria2)
    } else {
        None
    }
}

fn __query_shred(_url: &Url) -> HashMap<String, String> {
    let mut _bag = HashMap::new();
    for (_k, _v) in _url.query_pairs() {
        _bag.insert(_k.to_string(), _v.to_string());
    }
    _bag
}

fn __tag_pluck(_url: &Url, _fallback: &str) -> String {
    match _url.fragment() {
        Some(_frag) => urlencoding::decode(_frag)
            .map(|_c| _c.to_string())
            .unwrap_or_else(|_| _frag.to_string()),
        None => _fallback.to_string(),
    }
}

fn __vless_carve(_uri: &str) -> Option<_relay> {
    let _parsed = Url::parse(_uri).ok()?;
    Some(_relay {
        _kind: _kind::Vless,
        _addr: _parsed.host_str()?.to_string(),
        _port: _parsed.port()?,
        _secret: _parsed.username().to_string(),
        _tag: __tag_pluck(&_parsed, "vless"),
        _extra: __query_shred(&_parsed),
        source_repo: None,
        source_path: None,
        alive: None,
        ping_ms: None,
        checked_at: None,
    })
}

fn __trojan_carve(_uri: &str) -> Option<_relay> {
    let _parsed = Url::parse(_uri).ok()?;
    Some(_relay {
        _kind: _kind::Trojan,
        _addr: _parsed.host_str()?.to_string(),
        _port: _parsed.port()?,
        _secret: _parsed.username().to_string(),
        _tag: __tag_pluck(&_parsed, "trojan"),
        _extra: __query_shred(&_parsed),
        source_repo: None,
        source_path: None,
        alive: None,
        ping_ms: None,
        checked_at: None,
    })
}

fn __hy2_carve(_uri: &str) -> Option<_relay> {
    let ___normalized = _uri.replacen("hy2://", "hysteria2://", 1);
    let _parsed = Url::parse(&___normalized).ok()?;
    Some(_relay {
        _kind: _kind::Hysteria2,
        _addr: _parsed.host_str()?.to_string(),
        _port: _parsed.port()?,
        _secret: _parsed.username().to_string(),
        _tag: __tag_pluck(&_parsed, "hysteria2"),
        _extra: __query_shred(&_parsed),
        source_repo: None,
        source_path: None,
        alive: None,
        ping_ms: None,
        checked_at: None,
    })
}

fn __b64_loosen(_chunk: &str) -> Option<String> {
    use base64::{engine::general_purpose, Engine as _};
    let ___padded = match _chunk.len() % 4 {
        2 => format!("{_chunk}=="),
        3 => format!("{_chunk}="),
        _ => _chunk.to_string(),
    };
    general_purpose::URL_SAFE
        .decode(&___padded)
        .or_else(|_| general_purpose::STANDARD.decode(&___padded))
        .ok()
        .and_then(|_bytes| String::from_utf8(_bytes).ok())
}

fn __ss_legacy_carve(_decoded: &str, _tag: &str) -> Option<_relay> {
    let (_creds, _hostport) = _decoded.split_once('@')?;
    let (_method, _secret) = _creds.split_once(':')?;
    let (_addr, _port_str) = _hostport.split_once(':')?;
    let mut _extra = HashMap::new();
    _extra.insert("method".to_string(), _method.to_string());
    Some(_relay {
        _kind: _kind::Shadowsocks,
        _addr: _addr.to_string(),
        _port: _port_str.parse().ok()?,
        _secret: _secret.to_string(),
        _tag: _tag.to_string(),
        _extra,
        source_repo: None,
        source_path: None,
        alive: None,
        ping_ms: None,
        checked_at: None,
    })
}

fn __ss_carve(_uri: &str) -> Option<_relay> {
    let _body = _uri.strip_prefix("ss://")?;
    let (_head, _tag_raw) = _body.split_once('#').unwrap_or((_body, "ss"));
    let _tag = urlencoding::decode(_tag_raw)
        .map(|_c| _c.to_string())
        .unwrap_or_else(|_| _tag_raw.to_string());

    if let Some((_userinfo, _hostport)) = _head.split_once('@') {
        let _decoded = __b64_loosen(_userinfo)?;
        let (_method, _secret) = _decoded.split_once(':')?;
        let (_addr, _port_str) = _hostport.split_once(':')?;
        let ___port_clean: String = _port_str.chars().take_while(|_c| _c.is_ascii_digit()).collect();
        let mut _extra = HashMap::new();
        _extra.insert("method".to_string(), _method.to_string());
        return Some(_relay {
            _kind: _kind::Shadowsocks,
            _addr: _addr.to_string(),
            _port: ___port_clean.parse().ok()?,
            _secret: _secret.to_string(),
            _tag,
            _extra,
            source_repo: None,
            source_path: None,
            alive: None,
            ping_ms: None,
            checked_at: None,
        });
    }

    let _decoded = __b64_loosen(_head)?;
    __ss_legacy_carve(&_decoded, &_tag)
}

pub fn __single_carve(_uri: &str) -> Option<_relay> {
    match __scheme_sniff(_uri)? {
        _kind::Vless => __vless_carve(_uri),
        _kind::Trojan => __trojan_carve(_uri),
        _kind::Shadowsocks => __ss_carve(_uri),
        _kind::Hysteria2 => __hy2_carve(_uri),
    }
}

pub fn __blob_harvest(_blob: &str) -> Vec<_relay> {
    let _rx = Regex::new(r#"(?i)(vless|trojan|ss|hysteria2|hy2)://[^\s'"<>]+"#).unwrap();
    _rx.find_iter(_blob)
        .filter_map(|_m| __single_carve(_m.as_str()))
        .collect()
}

#[cfg(test)]
mod _tests {
    use super::*;

    #[test]
    fn __vless_sanity() {
        let _sample = "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?encryption=none&security=tls&type=ws#my-node";
        let _got = __single_carve(_sample).unwrap();
        assert_eq!(_got._kind, _kind::Vless);
        assert_eq!(_got._addr, "1.2.3.4");
        assert_eq!(_got._port, 443);
        assert_eq!(_got._tag, "my-node");
        assert_eq!(_got._extra.get("security").unwrap(), "tls");
    }

    #[test]
    fn __trojan_sanity() {
        let _sample = "trojan://sup3rpass@5.5.5.5:8443?sni=example.com#tj-node";
        let _got = __single_carve(_sample).unwrap();
        assert_eq!(_got._kind, _kind::Trojan);
        assert_eq!(_got._secret, "sup3rpass");
        assert_eq!(_got._port, 8443);
    }

    #[test]
    fn __hy2_alias_sanity() {
        let _sample = "hy2://pass123@9.9.9.9:36712?insecure=1#hy-node";
        let _got = __single_carve(_sample).unwrap();
        assert_eq!(_got._kind, _kind::Hysteria2);
        assert_eq!(_got._addr, "9.9.9.9");
    }

    #[test]
    fn __ss_userinfo_form_sanity() {
        let ___creds = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "aes-256-gcm:supersecret",
        );
        let _sample = format!("ss://{___creds}@5.6.7.8:8388#ss-node");
        let _got = __single_carve(&_sample).unwrap();
        assert_eq!(_got._kind, _kind::Shadowsocks);
        assert_eq!(_got._addr, "5.6.7.8");
        assert_eq!(_got._port, 8388);
        assert_eq!(_got._secret, "supersecret");
        assert_eq!(_got._extra.get("method").unwrap(), "aes-256-gcm");
    }

    #[test]
    fn __ss_legacy_form_sanity() {
        let ___whole = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "aes-256-gcm:supersecret@5.6.7.8:8388",
        );
        let _sample = format!("ss://{___whole}#legacy-node");
        let _got = __single_carve(&_sample).unwrap();
        assert_eq!(_got._kind, _kind::Shadowsocks);
        assert_eq!(_got._addr, "5.6.7.8");
        assert_eq!(_got._port, 8388);
    }

    #[test]
    fn __harvest_mixed_blob() {
        let _blob = "junk text\nvless://aaa@1.1.1.1:443?type=ws#a\nmore junk here\ntrojan://pwd@2.2.2.2:8443#b\nrandom line ss://Zm9vOmJhcg==@3.3.3.3:1080#c\n";
        let _got = __blob_harvest(_blob);
        assert_eq!(_got.len(), 3);
    }

    #[test]
    fn __garbage_rejected() {
        assert!(__single_carve("http://not-a-relay.com").is_none());
        assert!(__single_carve("vless://broken-no-host").is_none());
    }
}
