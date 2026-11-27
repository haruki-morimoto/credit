use std::env;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::{self, Command};

use credit_gateway::explorer::{DEFAULT_EXPLORER_SEEDS, serve_explorer};
use credit_gateway::live_wallet::serve_live_wallet_gateway_full;
use credit_gateway::serve_gateway;

fn try_open_browser(url: &str) {
    if cfg!(target_os = "windows") {
        let _ = Command::new("cmd").args(["/C", "start", "", url]).spawn();
    } else if cfg!(target_os = "macos") {
        let _ = Command::new("open").arg(url).spawn();
    } else {
        let _ = Command::new("xdg-open").arg(url).spawn();
    }
}

fn main() {
    let mut bind_addr = String::from("127.0.0.1:8080");
    let mut data_dir = PathBuf::from("./gateway-data");
    let mut explorer_mode = false;
    let mut open_browser = false;
    let mut live_node_addr: Option<SocketAddr> = None;
    let mut wallet_path: Option<PathBuf> = None;
    let mut password_opt: Option<String> = None;
    let mut webhook_url: Option<String> = None;
    let mut webhook_secret = String::from("whsec_xcr_default");
    let mut network_label = String::from("Live P2P Mesh");
    let mut custom_seeds: Vec<(String, SocketAddr)> = Vec::new();

    let args: Vec<String> = env::args().skip(1).collect();
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--http" if i + 1 < args.len() => {
                bind_addr = args[i + 1].clone();
                i += 2;
            }
            "--data-dir" if i + 1 < args.len() => {
                data_dir = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            "--testnet" => {
                live_node_addr.get_or_insert_with(|| "162.243.166.102:9501".parse().unwrap());
                network_label = String::from("Global Public Testnet");
                i += 1;
            }
            "--open" => {
                open_browser = true;
                i += 1;
            }
            "--node" if i + 1 < args.len() => {
                let parsed: SocketAddr = args[i + 1].parse().unwrap_or_else(|e| {
                    eprintln!("invalid --node socket '{}': {e}", args[i + 1]);
                    process::exit(2);
                });
                live_node_addr = Some(parsed);
                i += 2;
            }
            "--wallet" if i + 1 < args.len() => {
                wallet_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--password" if i + 1 < args.len() => {
                password_opt = Some(args[i + 1].clone());
                i += 2;
            }
            "--webhook" if i + 1 < args.len() => {
                webhook_url = Some(args[i + 1].clone());
                i += 2;
            }
            "--webhook-secret" if i + 1 < args.len() => {
                webhook_secret = args[i + 1].clone();
                i += 2;
            }
            "--explorer" => {
                explorer_mode = true;
                i += 1;
            }
            "--seeds" if i + 1 < args.len() => {
                explorer_mode = true;
                for entry in args[i + 1]
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    let (label, raw_addr) = entry.split_once('=').unwrap_or((entry, entry));
                    let parsed: SocketAddr = raw_addr.parse().unwrap_or_else(|e| {
                        eprintln!("invalid seed socket '{raw_addr}': {e}");
                        process::exit(2);
                    });
                    custom_seeds.push((label.to_owned(), parsed));
                }
                i += 2;
            }
            other => {
                eprintln!(
                    "Usage: credit-gateway [--http 127.0.0.1:8080] [--testnet] [--node IP:PORT] [--wallet PATH] [--password PASS] [--open] [--data-dir PATH] [--explorer] [--seeds Name=IP:PORT,...] (got '{other}')"
                );
                process::exit(2);
            }
        }
    }

    let listener = TcpListener::bind(&bind_addr).unwrap_or_else(|e| {
        eprintln!("failed to bind HTTP gateway at {bind_addr}: {e}");
        process::exit(1);
    });
    let actual = listener.local_addr().unwrap();
    let browser_url = format!("http://{actual}");

    if explorer_mode {
        if custom_seeds.is_empty() {
            custom_seeds = DEFAULT_EXPLORER_SEEDS
                .iter()
                .map(|&(name, addr)| (name.to_owned(), addr.parse().unwrap()))
                .collect();
        }
        println!("==========================================================================");
        println!("  Credits (∀ / XCR) — Live Global Public Testnet Explorer");
        println!("  Listening on: {browser_url}");
        println!("==========================================================================");
        if open_browser {
            try_open_browser(&browser_url);
        }
        if let Err(err) = serve_explorer(listener, custom_seeds) {
            eprintln!("explorer error: {err}");
            process::exit(1);
        }
        return;
    }

    if live_node_addr.is_some() || wallet_path.is_some() {
        let target_node = live_node_addr.unwrap_or_else(|| "162.243.166.102:9501".parse().unwrap());
        let w_path = wallet_path.unwrap_or_else(|| PathBuf::from("./credit.wallet"));
        println!("==========================================================================");
        println!("  Credits (∀ / XCR) — Live Network Wallet & Merchant POS Terminal");
        println!("  Connected Node : {target_node} ({network_label})");
        println!("  Wallet Seed    : {}", w_path.display());
        println!("  Open in browser: {browser_url}");
        println!("==========================================================================");
        if open_browser {
            try_open_browser(&browser_url);
        }
        if let Err(err) = serve_live_wallet_gateway_full(
            listener,
            &w_path,
            password_opt.as_deref(),
            target_node,
            network_label,
            webhook_url,
            webhook_secret,
        ) {
            eprintln!("live wallet gateway error: {err}");
            process::exit(1);
        }
        return;
    }

    println!("==========================================================================");
    println!("  Credits (∀ / XCR) — Consumer Wallet & Merchant POS Gateway");
    println!("  Open in browser: {browser_url}");
    println!("==========================================================================");
    if open_browser {
        try_open_browser(&browser_url);
    }

    if let Err(err) = serve_gateway(listener, &data_dir) {
        eprintln!("gateway error: {err}");
        process::exit(1);
    }
}
