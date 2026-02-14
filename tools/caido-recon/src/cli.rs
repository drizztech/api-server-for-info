use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// List of target URLs or domains
    #[arg(short, long, value_delimiter = ',', num_args = 1..)]
    pub targets: Vec<String>,

    /// Path to file containing targets (one per line)
    #[arg(short, long)]
    pub file: Option<String>,

    /// Chaos API Key
    #[arg(long, env = "CHAOS_KEY")]
    pub chaos_key: Option<String>,

    /// Google API Key
    #[arg(long, env = "GOOGLE_API_KEY")]
    pub google_key: Option<String>,

    /// Google CX
    #[arg(long, env = "GOOGLE_CX")]
    pub google_cx: Option<String>,

    /// Bing API Key
    #[arg(long, env = "BING_API_KEY")]
    pub bing_key: Option<String>,

    /// Intigriti API Key
    #[arg(long, env = "INTIGRITI_KEY")]
    pub intigriti_key: Option<String>,

    /// Output format (json-stream is default and only option for now)
    #[arg(long, default_value = "json-stream")]
    pub format: String,
}
