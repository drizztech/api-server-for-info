# Fatalis Proxy & Analyzer

This toolset provides a proxy and analysis pipeline for the White Fatalis Framework.

## Components

### 1. Fatalis Proxy (Rust)
A multi-purpose tool that:
*   **Pipelines**: Orchestrates `caido-recon` and `recon_analyzer.py`.
*   **Proxy**: Acts as a WAF bypass proxy (header manipulation).
*   **Server**: Simple callback server for OOB testing.

### 2. Recon Analyzer (Python)
An analysis script that:
*   Reads recon data (JSON stream) from stdin.
*   Enriches findings using Gemini (Google AI) and/or Ollama (Local LLM).

## Usage

### Build
```bash
cargo build --release
```
The binary will be at `target/release/fatalis-proxy`.

### Run Pipeline
Scans targets with `caido-recon` and analyzes results with AI.
```bash
./fatalis-proxy run-pipeline --targets example.com --use-gemini --use-ollama
```
*   `--use-gemini`: Requires `GEMINI_API_KEY` env var.
*   `--use-ollama`: Requires local Ollama running on port 11434.

### WAF Bypass Proxy
Starts a proxy on port 8080 that adds evasion headers.
```bash
./fatalis-proxy proxy --port 8080
```

### Callback Server
Starts a server on port 9090 to log incoming requests (useful for blind XSS/SSRF).
```bash
./fatalis-proxy server --port 9090
```

## Requirements
*   Python 3 with dependencies (`pip install -r requirements.txt`)
*   `caido-recon` binary built in `../caido-recon/`
