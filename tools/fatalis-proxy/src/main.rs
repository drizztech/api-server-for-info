use clap::{Parser, Subcommand};
use std::process::{Command, Stdio};
use std::convert::Infallible;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server, Client};
use hyper_tls::HttpsConnector;
use std::io::{BufReader, BufRead};
use std::path::Path;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run the full recon pipeline (caido-recon -> python analyzer)
    RunPipeline {
        /// Targets to scan
        #[arg(short, long, value_delimiter = ',', num_args = 1..)]
        targets: Vec<String>,

        /// Use Gemini for analysis
        #[arg(long)]
        use_gemini: bool,

        /// Use Ollama for analysis
        #[arg(long)]
        use_ollama: bool,
    },
    /// Start a WAF bypass proxy
    Proxy {
        /// Port to listen on
        #[arg(short, long, default_value = "8080")]
        port: u16,
    },
    /// Start a callback server for redirect testing
    Server {
        /// Port to listen on
        #[arg(short, long, default_value = "9090")]
        port: u16,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args = Args::parse();

    match args.command {
        Commands::RunPipeline { targets, use_gemini, use_ollama } => {
            run_pipeline(targets, use_gemini, use_ollama).await?;
        }
        Commands::Proxy { port } => {
            start_proxy(port).await?;
        }
        Commands::Server { port } => {
            start_server(port).await?;
        }
    }

    Ok(())
}

async fn run_pipeline(targets: Vec<String>, use_gemini: bool, use_ollama: bool) -> anyhow::Result<()> {
    println!("Starting Pipeline...");

    // Resolve paths better. Try release, then debug, then assume in PATH or same dir.
    let possible_paths = vec![
        "./tools/caido-recon/target/release/caido-recon",
        "./tools/caido-recon/target/debug/caido-recon",
        "caido-recon"
    ];

    let caido_recon_path = possible_paths.iter()
        .find(|p| Path::new(p).exists())
        .unwrap_or(&"caido-recon");

    let analyzer_path = "tools/recon_analyzer.py";

    // 1. Start caido-recon
    let mut recon_cmd = Command::new(caido_recon_path)
        .arg("--targets")
        .args(&targets)
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start caido-recon. Is it built?");

    let recon_stdout = recon_cmd.stdout.take().expect("Failed to open caido-recon stdout");

    // 2. Start python analyzer
    let mut analyzer_args = vec![analyzer_path.to_string()];
    if use_gemini { analyzer_args.push("--use-gemini".to_string()); }
    if use_ollama { analyzer_args.push("--use-ollama".to_string()); }

    let mut analyzer_cmd = Command::new("python3")
        .args(&analyzer_args)
        .stdin(Stdio::from(recon_stdout)) // Pipe directly
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to start python analyzer");

    // 3. Stream output from analyzer to stdout line by line
    if let Some(stdout) = analyzer_cmd.stdout.take() {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            match line {
                Ok(l) => println!("{}", l),
                Err(e) => eprintln!("Error reading line: {}", e),
            }
        }
    }

    let _ = analyzer_cmd.wait();
    let _ = recon_cmd.wait();

    Ok(())
}

async fn start_server(port: u16) -> anyhow::Result<()> {
    let addr = ([0, 0, 0, 0], port).into();

    let make_svc = make_service_fn(|_conn| async {
        Ok::<_, Infallible>(service_fn(handle_callback))
    });

    println!("Callback server listening on http://{}", addr);

    let server = Server::bind(&addr).serve(make_svc);

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
    Ok(())
}

async fn handle_callback(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    println!("Received request: {} {}", req.method(), req.uri());
    println!("Headers: {:?}", req.headers());
    Ok(Response::new(Body::from("Logged")))
}

async fn start_proxy(port: u16) -> anyhow::Result<()> {
    let addr = ([0, 0, 0, 0], port).into();

    let make_svc = make_service_fn(|_conn| async {
        Ok::<_, Infallible>(service_fn(handle_proxy))
    });

    println!("WAF Bypass Proxy listening on http://{}", addr);

    let server = Server::bind(&addr).serve(make_svc);

    if let Err(e) = server.await {
        eprintln!("proxy error: {}", e);
    }

    Ok(())
}

async fn handle_proxy(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, hyper::Body>(https);

    let (parts, body) = req.into_parts();
    // let mut uri_string = parts.uri.to_string();

    // Simple logic: if request comes to proxy as "GET http://target.com/...", hyper parses it.
    // We want to forward it.

    // WAF Bypass Logic:
    // 1. Case switching (Host header) - hyper might normalize this, but we can try.
    // 2. Add fake headers.

    let mut req_builder = Request::builder()
        .method(parts.method)
        .uri(parts.uri);

    for (k, v) in parts.headers.iter() {
        // Skip hop-by-hop
        if k == "host" {
             // Example bypass: Mix case? Hyper headers are lowercase.
             // We can manually append it later?
             req_builder = req_builder.header(k, v);
        } else {
             req_builder = req_builder.header(k, v);
        }
    }

    // Add bypass headers
    req_builder = req_builder.header("X-Forwarded-For", "127.0.0.1");
    req_builder = req_builder.header("X-Originating-IP", "127.0.0.1");
    req_builder = req_builder.header("X-Remote-IP", "127.0.0.1");
    req_builder = req_builder.header("X-Client-IP", "127.0.0.1");

    let proxy_req = req_builder.body(body).unwrap();

    // In a real proxy we would handle HTTPS CONNECT, but here we assume HTTP for simplicity
    // or that the client sends absolute URIs.

    let res = client.request(proxy_req).await?;
    Ok(res)
}
