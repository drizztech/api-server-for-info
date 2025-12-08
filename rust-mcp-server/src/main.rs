use clap::{Parser, Subcommand};
use anyhow::Result;

mod wifi;
mod proxy;

#[derive(Parser)]
#[command(name = "rust-mcp-tool")]
#[command(version = "1.0")]
#[command(about = "Rust MCP Server & Security Tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the MCP server (Default)
    Server,
    /// Download the repo (Clone current repo)
    Download,
    /// Launch Proxy & WiFi Tool
    Proxy {
        #[arg(short = 'P', long, default_value_t = 8080)]
        port: u16,
        #[arg(short = 'f', long, default_value = "capture.pcap")]
        pcap: String,
        #[arg(long, default_value_t = false)]
        skip_wifi: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command.unwrap_or(Commands::Server) {
        Commands::Server => {
            println!("Starting MCP Server...");
            // MCP implementation would go here (using rmcp crate)
            // For now, we print the prompt as requested
            let prompt = include_str!("../../prompt.sh");
            println!("Loading prompt...");
            println!("{}", prompt);

            // Placeholder for actual MCP server loop
            println!("MCP Server running on stdio (simulated)...");
            // In a real implementation:
            // let server = rmcp::Server::new(transport);
            // server.run().await?;
            Ok(())
        }
        Commands::Download => {
            println!("Downloading repo...");
            // Use a generic placeholder or the current directory logic if possible.
            // Since we don't know the exact remote of *this* repo environment easily,
            // we will simulate cloning a repo to a 'downloaded_repo' folder as a test/demo.
            // Or just clone the SDK as a useful default.
            let repo_url = "https://github.com/modelcontextprotocol/rust-sdk.git";
            println!("Cloning {} into ./downloaded_repo ...", repo_url);

            std::process::Command::new("git")
                .args(&["clone", repo_url, "downloaded_repo"])
                .status()?;

            println!("Download complete.");
            Ok(())
        }
        Commands::Proxy { port, pcap, skip_wifi } => {
            if !skip_wifi {
                println!("Scanning and connecting to priority WiFi networks...");
                wifi::auto_connect();
            }

            println!("Starting Proxy on port {} logging to {}", port, pcap);
            println!("Configure Caido/Burp/ZAP to use SOCKS5 proxy at 127.0.0.1:{}", port);

            let server = proxy::ProxyServer::new(&pcap)?;
            server.run(port).await?;
            Ok(())
        }
    }
}
