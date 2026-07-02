#![allow(non_camel_case_types)]

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(name = "rifter", version, about = "Discover, validate and export free VPN configs scraped from GitHub")]
pub struct _cli {
    #[command(subcommand)]
    pub _cmd: _cmd,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum _proto {
    Vless,
    Trojan,
    Ss,
    Hysteria2,
    All,
}

#[derive(Subcommand, Debug)]
pub enum _cmd {
    Crawl {
        #[arg(long = "github-token", env = "GITHUB_TOKEN")]
        _token: String,

        #[arg(long = "protocol", value_enum, default_value = "all")]
        _protocols: Vec<_proto>,

        #[arg(long = "max-results", default_value_t = 50)]
        _max_results: usize,

        #[arg(long, default_value_t = 150)]
        _concurrency: usize,

        #[arg(long, default_value_t = 3000)]
        _timeout: u64,

        #[arg(long, default_value = "configs/all.json")]
        _output: String,

        #[arg(long = "dry-run", default_value_t = false)]
        _dry_run: bool,
    },

    Validate {
        #[arg(long, default_value = "configs/all.json")]
        _input: String,

        #[arg(long, default_value_t = 150)]
        _concurrency: usize,

        #[arg(long, default_value_t = 3000)]
        _timeout: u64,

        #[arg(long, default_value_t = false)]
        _prune: bool,
    },

    Search {
        #[arg(long, default_value = "configs/all.json")]
        _input: String,

        #[arg(long = "protocol", value_enum)]
        _protocol: Option<_proto>,

        #[arg(long = "max-ping")]
        _max_ping: Option<u64>,

        #[arg(long)]
        _host: Option<String>,

        #[arg(long, default_value_t = 50)]
        _limit: usize,
    },

    Export {
        #[arg(long, default_value = "configs/all.json")]
        _input: String,

        #[arg(long, value_enum, default_value = "table")]
        _format: _fmt,

        #[arg(long, default_value_t = 20)]
        _limit: usize,
    },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum _fmt {
    Table,
    Json,
}
