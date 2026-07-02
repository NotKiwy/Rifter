#![allow(non_camel_case_types, non_upper_case_globals)]

use crate::parser::{__blob_harvest, _kind, _relay};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use serde::Deserialize;
use std::time::Duration;

const _agent: &str = "rifter-cli";
const _api_ver: &str = "2022-11-28";
const _throttle: Duration = Duration::from_millis(2200);

pub struct _hub {
    _http: reqwest::Client,
    _token: String,
}

#[derive(Debug, Clone)]
pub struct _hit {
    pub _repo: String,
    pub _path: String,
    pub _url: String,
}

#[derive(Deserialize)]
struct ___search_reply {
    #[serde(default)]
    items: Vec<___search_row>,
}

#[derive(Deserialize)]
struct ___search_row {
    path: String,
    url: String,
    repository: ___repo_row,
}

#[derive(Deserialize)]
struct ___repo_row {
    full_name: String,
}

#[derive(Deserialize)]
struct ___contents_reply {
    content: Option<String>,
    encoding: Option<String>,
}

impl _hub {
    pub fn __spawn(_token: impl Into<String>) -> Result<Self> {
        let _http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .context("building HTTP client")?;
        Ok(Self { _http, _token: _token.into() })
    }

    fn __badge(&self) -> Vec<(&'static str, String)> {
        vec![
            ("Authorization", format!("Bearer {}", self._token)),
            ("User-Agent", _agent.to_string()),
            ("Accept", "application/vnd.github+json".to_string()),
            ("X-GitHub-Api-Version", _api_ver.to_string()),
        ]
    }

    fn __needles_for(_kind: _kind) -> &'static [&'static str] {
        match _kind {
            _kind::Vless => &["\"vless://\""],
            _kind::Trojan => &["\"trojan://\""],
            _kind::Shadowsocks => &["\"ss://\""],
            _kind::Hysteria2 => &["\"hysteria2://\"", "\"hy2://\""],
        }
    }

    pub async fn __trawl(&self, _needle: &str, _cap: usize) -> Result<Vec<_hit>> {
        let mut _hits = Vec::new();
        let _per_page = _cap.min(100).max(1);
        let mut _page = 1u32;

        while _hits.len() < _cap {
            tokio::time::sleep(_throttle).await;

            let mut _req = self
                ._http
                .get("https://api.github.com/search/code")
                .query(&[
                    ("q", _needle.to_string()),
                    ("per_page", _per_page.to_string()),
                    ("page", _page.to_string()),
                ]);
            for (_k, _v) in self.__badge() {
                _req = _req.header(_k, _v);
            }

            let _resp = _req.send().await.context("sending GitHub search request")?;
            let _status = _resp.status();

            if _status == reqwest::StatusCode::FORBIDDEN || _status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                eprintln!("  rate limited on query {_needle:?}, backing off 30s...");
                tokio::time::sleep(Duration::from_secs(30)).await;
                continue;
            }
            if !_status.is_success() {
                let ___body = _resp.text().await.unwrap_or_default();
                bail!("GitHub search failed ({_status}) for query {_needle:?}: {___body}");
            }

            let _parsed: ___search_reply = _resp.json().await.context("parsing GitHub search response")?;
            if _parsed.items.is_empty() {
                break;
            }

            let ___got = _parsed.items.len();
            for _item in _parsed.items {
                if _hits.len() >= _cap {
                    break;
                }
                _hits.push(_hit {
                    _repo: _item.repository.full_name,
                    _path: _item.path,
                    _url: _item.url,
                });
            }

            if ___got < _per_page {
                break;
            }
            _page += 1;
        }

        Ok(_hits)
    }

    pub async fn __slurp(&self, _contents_url: &str) -> Result<String> {
        let mut _req = self._http.get(_contents_url);
        for (_k, _v) in self.__badge() {
            _req = _req.header(_k, _v);
        }
        let _resp = _req.send().await.context("fetching file contents")?;
        if !_resp.status().is_success() {
            bail!("failed to fetch {_contents_url}: {}", _resp.status());
        }
        let _parsed: ___contents_reply = _resp.json().await.context("parsing contents response")?;
        let (Some(_content), Some(_encoding)) = (_parsed.content, _parsed.encoding) else {
            bail!("contents response had no inline body (file may be too large)");
        };
        if _encoding != "base64" {
            bail!("unexpected content encoding: {_encoding}");
        }
        let ___cleaned: String = _content.chars().filter(|_c| !_c.is_whitespace()).collect();
        let _bytes = general_purpose::STANDARD
            .decode(___cleaned)
            .context("decoding base64 file content")?;
        Ok(String::from_utf8_lossy(&_bytes).into_owned())
    }

    pub async fn __excavate(&self, _kind: _kind, _cap: usize) -> Result<Vec<_relay>> {
        let mut _found = Vec::new();
        let _needles = Self::__needles_for(_kind);
        let _per_needle_cap = (_cap / _needles.len().max(1)).max(1);

        for _needle in _needles {
            eprintln!("  searching GitHub for {_needle} (protocol: {_kind})...");
            let _hits = self.__trawl(_needle, _per_needle_cap).await?;
            eprintln!("    {} candidate file(s)", _hits.len());

            for _hit in _hits {
                let _text = match self.__slurp(&_hit._url).await {
                    Ok(_t) => _t,
                    Err(_e) => {
                        eprintln!("    skip {}: {_e}", _hit._path);
                        continue;
                    }
                };
                for mut _relay in __blob_harvest(&_text) {
                    if _relay._kind == _kind {
                        _relay._source_repo = Some(_hit._repo.clone());
                        _relay._source_path = Some(_hit._path.clone());
                        _found.push(_relay);
                    }
                }
            }
        }

        Ok(_found)
    }
}
