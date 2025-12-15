mod cli;
mod apis;
mod scanner;
mod vulns;

use clap::Parser;
use std::fs::File;
use std::io::{self, BufRead};
use reqwest::Client;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = cli::Args::parse();

    let mut targets = args.targets.clone();

    if let Some(file_path) = args.file {
        if let Ok(file) = File::open(file_path) {
            let lines = io::BufReader::new(file).lines();
            for line in lines {
                if let Ok(l) = line {
                    if !l.trim().is_empty() {
                        targets.push(l.trim().to_string());
                    }
                }
            }
        }
    }

    // Query APIs to expand target list if keys are provided
    // For now, we just pick the first target if available as a seed, or skip if empty.
    if let Some(first_target) = targets.first() {
        if let Ok(chaos_targets) = apis::query_chaos(first_target, args.chaos_key.as_deref()).await {
             targets.extend(chaos_targets.iter().map(|s| s.domain.clone()));
        }
    }

    // Note: Other APIs (Google/Bing) would typically require a search query, not just a target list.
    // For now, we assume the user provides specific targets or we'd need a search term argument.

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .user_agent("Caido-Recon/0.1")
        .build()?;

    // Process targets
    // For now simple loop, could be concurrent
    for target in targets {
        // Ensure protocol
        let url = if target.starts_with("http") {
            target
        } else {
            format!("https://{}", target)
        };

        match scanner::scan_url(&client, &url).await {
            Ok(result) => {
                let json = serde_json::to_string(&result)?;
                println!("{}", json);
            },
            Err(e) => {
                // Log error in json stream format too?
                let err_json = serde_json::json!({
                    "target": url,
                    "error": e.to_string()
                });
                eprintln!("{}", err_json);
            }
        }
    }

    Ok(())
}
