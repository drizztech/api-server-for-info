# Caido Recon Tool

This is a Rust-based CLI tool designed to be used with Caido (or standalone) for reconnaissance and vulnerability scanning.

## Features

- **File Discovery**: Crawls target pages to find referenced `.js` and `.html` files.
- **Header Analysis**: Checks for missing security headers (HSTS, CSP) and information leakage (Server, X-Powered-By).
- **API Logic Heuristics**: flags potential API logic errors (e.g., 5xx errors on `/api/` endpoints).
- **JSON Stream Output**: Outputs results as a stream of JSON objects, suitable for piping into other tools or Caido.
- **External API Integration**: placeholders for Chaos, Google, Bing, and Intigriti APIs (requires implementation with valid keys).

## Installation

1.  Ensure you have Rust installed.
2.  Navigate to `tools/caido-recon`.
3.  Build the project:
    ```bash
    cargo build --release
    ```
4.  The binary will be at `target/release/caido-recon`.

## Usage

### Basic Scan
```bash
./caido-recon --targets https://example.com,https://api.example.com
```

### From File
```bash
./caido-recon --file targets.txt
```

### With API Keys (Future Support)
```bash
export CHAOS_KEY="your_key"
./caido-recon --targets example.com --chaos_key $CHAOS_KEY
```

## Integration with Caido

You can use this tool within Caido by defining a "Command" in your workflow that executes this binary and parses the JSON output.

## Output Format

The tool outputs one JSON object per line:

```json
{
  "url": "https://example.com/",
  "status": 200,
  "headers": {
    "content-type": "text/html",
    "server": "Apache"
  },
  "js_files": ["https://example.com/app.js"],
  "html_files": ["https://example.com/about.html"],
  "vulns": [
    {
      "check_type": "Header",
      "message": "Missing Strict-Transport-Security header",
      "severity": "Low"
    }
  ]
}
```
